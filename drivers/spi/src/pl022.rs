//! ARM PrimeCell PL022 SPI controller driver.
//!
//! Provides support for the ARM PL022 Synchronous Serial Port (SSP)
//! controller, ubiquitous across many ARM platforms.
//!
//! References: `linux/drivers/spi/spi-pl022.c`

extern crate alloc;

use alloc::string::String;

use narf_memory::PhysAddr;
use narf_lib::sync::IrqSafeSpinLock;

use crate::{SpiBus, SpiError, SpiMode};

// ── Register offsets ───────────────────────────────────────────────

const PL022_CR0: u64  = 0x00; // Control Register 0
const PL022_CR1: u64  = 0x04; // Control Register 1
const PL022_DR: u64   = 0x08; // Data Register
const PL022_SR: u64   = 0x0C; // Status Register
const PL022_CPSR: u64 = 0x10; // Clock Prescale Register
const PL022_IMSC: u64 = 0x14; // Interrupt Mask Set and Clear

const PL022_CR0_DSS_8BIT: u32 = 0x07; // 8-bit data
const PL022_CR0_SPO: u32      = 1 << 6;
const PL022_CR0_SPH: u32      = 1 << 7;

const PL022_CR1_SSE: u32 = 1 << 1; // SSP Enable

const PL022_SR_TFE: u32 = 1 << 0; // Transmit FIFO empty
const PL022_SR_TNF: u32 = 1 << 1; // Transmit FIFO not full
const PL022_SR_RNE: u32 = 1 << 2; // Receive FIFO not empty
const PL022_SR_BSY: u32 = 1 << 4; // Busy

// ── Controller struct ──────────────────────────────────────────────

#[derive(Debug)]
pub struct Pl022Spi {
    name: String,
    mmio_base: PhysAddr,
    state: IrqSafeSpinLock<()>,
}

impl Pl022Spi {
    pub fn new(name: String, mmio_base: PhysAddr) -> Self {
        let spi = Self {
            name,
            mmio_base,
            state: IrqSafeSpinLock::new(()),
        };
        // Disable SSP
        let mut cr1 = spi.read_u32(PL022_CR1);
        cr1 &= !PL022_CR1_SSE;
        spi.write_u32(PL022_CR1, cr1);

        // Set 8-bit data, Motorola SPI frame format
        let mut cr0 = spi.read_u32(PL022_CR0);
        cr0 = (cr0 & !0x3F) | PL022_CR0_DSS_8BIT;
        spi.write_u32(PL022_CR0, cr0);

        // Mask all interrupts
        spi.write_u32(PL022_IMSC, 0);

        // Enable SSP
        cr1 |= PL022_CR1_SSE;
        spi.write_u32(PL022_CR1, cr1);
        spi
    }

    fn read_u32(&self, off: u64) -> u32 {
        unsafe { narf_arch::mmio::read32(self.mmio_base.raw() + off) }
    }

    fn write_u32(&self, off: u64, val: u32) {
        unsafe { narf_arch::mmio::write32(self.mmio_base.raw() + off, val) }
    }

    fn read_rx(&self) -> u32 {
        self.read_u32(PL022_DR)
    }

    fn write_tx(&self, val: u32) {
        self.write_u32(PL022_DR, val);
    }
}

impl SpiBus for Pl022Spi {
    fn name(&self) -> &str {
        &self.name
    }

    fn transfer(&self, tx: &[u8], rx: &mut [u8]) -> Result<(), SpiError> {
        let _guard = self.state.lock();
        
        let len = core::cmp::max(tx.len(), rx.len());
        for i in 0..len {
            let out_byte = if i < tx.len() { tx[i] } else { 0 };
            
            // Wait for TX room
            let mut timeout = 100_000;
            while (self.read_u32(PL022_SR) & PL022_SR_TNF) == 0 {
                timeout -= 1;
                if timeout == 0 {
                    return Err(SpiError::Timeout);
                }
                core::hint::spin_loop();
            }
            
            self.write_tx(out_byte as u32);
            
            // Wait for RX ready
            timeout = 100_000;
            while (self.read_u32(PL022_SR) & PL022_SR_RNE) == 0 {
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
        
        // Wait until totally idle
        let mut timeout = 100_000;
        while (self.read_u32(PL022_SR) & PL022_SR_BSY) != 0 {
            timeout -= 1;
            if timeout == 0 {
                return Err(SpiError::Timeout);
            }
            core::hint::spin_loop();
        }
        
        Ok(())
    }

    fn transfer_full_duplex(&self, tx: &mut [u8], rx: &mut [u8]) -> Result<(), SpiError> {
        let len = core::cmp::min(tx.len(), rx.len());
        self.transfer(&tx[..len], &mut rx[..len])
    }

    fn set_mode(&self, mode: SpiMode) -> Result<(), SpiError> {
        let _guard = self.state.lock();
        
        // Must disable SSP before changing CR0
        let cr1 = self.read_u32(PL022_CR1);
        self.write_u32(PL022_CR1, cr1 & !PL022_CR1_SSE);
        
        let mut cr0 = self.read_u32(PL022_CR0);
        
        if mode.cpol() {
            cr0 |= PL022_CR0_SPO;
        } else {
            cr0 &= !PL022_CR0_SPO;
        }
        
        if mode.cpha() {
            cr0 |= PL022_CR0_SPH;
        } else {
            cr0 &= !PL022_CR0_SPH;
        }
        
        self.write_u32(PL022_CR0, cr0);
        
        // Re-enable SSP
        self.write_u32(PL022_CR1, cr1);
        Ok(())
    }

    fn set_freq(&self, _hz: u32) -> Result<(), SpiError> {
        // Frequency setting involves CPSR and SCR in CR0.
        // Needs clock framework.
        Ok(())
    }

    fn set_cs(&self, _cs: u8) -> Result<(), SpiError> {
        // PL022 CS is typically managed via GPIOs in Linux.
        // We will leave this as a no-op or stub for now.
        Ok(())
    }
}

/// Probe for PL022 SPI controllers.
pub fn probe_all() -> usize {
    // Basic DT / AMBA Platform device probing placeholder.
    // PL022 is an AMBA primecell.
    0
}
