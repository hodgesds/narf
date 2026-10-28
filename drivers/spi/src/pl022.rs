//! ARM PrimeCell PL022 SPI controller driver.
//!
//! Provides support for the ARM PL022 Synchronous Serial Port (SSP)
//! controller, ubiquitous across many ARM platforms.
//!
//! References: `linux/drivers/spi/spi-pl022.c`
//!
//! DT programme step 5: the controller binds from devicetree
//! (`arm,pl022`, see [`probe_dt`]) over an ioremap'd window and
//! registers into the crate's shared bus registry. The input
//! clock (SSPCLK) resolves at probe time from the node's
//! `clocks` phandle (bus spec §3.1); without one the binding
//! falls back to [`SSPCLK_FALLBACK_HZ`]. `set_freq` is real: it
//! programs CPSR + CR0.SCR from that clock via [`divisor_for`].
//! Chip-select stays a no-op — PL022 CS is board GPIO in the
//! reference design (Linux drives it via GPIO lines), and no DT
//! cs-gpios consumer exists yet.

extern crate alloc;

use alloc::string::String;

use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::ioremap::IoMapping;
use narf_memory::PhysAddr;

use crate::{SpiBus, SpiError, SpiMode};

// ── Register offsets ───────────────────────────────────────────────

const PL022_CR0: u64 = 0x00; // Control Register 0
const PL022_CR1: u64 = 0x04; // Control Register 1
const PL022_DR: u64 = 0x08; // Data Register
const PL022_SR: u64 = 0x0C; // Status Register
const PL022_CPSR: u64 = 0x10; // Clock Prescale Register
const PL022_IMSC: u64 = 0x14; // Interrupt Mask Set and Clear

/// SSPCLK fallback when the DT node carries no usable `clocks`
/// phandle: the 24 MHz APB clock class PL011 also assumes on
/// virt-class boards. A placeholder constant consumed per bus
/// spec §3.1 until the clock framework (#1052) lands — boards
/// whose SSPCLK differs must describe it in DT.
pub const SSPCLK_FALLBACK_HZ: u32 = 24_000_000;

const PL022_CR0_DSS_8BIT: u32 = 0x07; // 8-bit data
const PL022_CR0_SPO: u32 = 1 << 6;
const PL022_CR0_SPH: u32 = 1 << 7;

const PL022_CR1_SSE: u32 = 1 << 1; // SSP Enable

const PL022_SR_TNF: u32 = 1 << 1; // Transmit FIFO not full
const PL022_SR_RNE: u32 = 1 << 2; // Receive FIFO not empty
const PL022_SR_BSY: u32 = 1 << 4; // Busy

// ── Controller struct ──────────────────────────────────────────────

#[derive(Debug)]
pub struct Pl022Spi {
    name: String,
    /// Access base: the phys window itself in the legacy form,
    /// the ioremap VA in the DT-bound form.
    base_va: u64,
    /// Kept so the ioremap lives as long as the controller;
    /// `None` for the phys form.
    _mapping: Option<IoMapping>,
    /// SSP input clock in Hz (0 = unknown; `set_freq` then
    /// refuses). Fixed at construction — SSPCLK does not change
    /// under a bound controller.
    sspclk_hz: u32,
    state: IrqSafeSpinLock<()>,
}

impl Pl022Spi {
    pub fn new(name: String, mmio_base: PhysAddr) -> Self {
        let spi = Self {
            name,
            base_va: mmio_base.raw(),
            _mapping: None,
            sspclk_hz: 0,
            state: IrqSafeSpinLock::new(()),
        };
        spi.init_regs();
        spi
    }

    /// Construct over an ioremap'd window with a known SSPCLK
    /// (the DT binding's form).
    ///
    /// # Safety
    /// `mapping` must cover the PL022 register block (4 KiB).
    pub unsafe fn new_mapped(name: String, mapping: IoMapping, sspclk_hz: u32) -> Self {
        let spi = Self {
            name,
            base_va: mapping.va(),
            _mapping: Some(mapping),
            sspclk_hz,
            state: IrqSafeSpinLock::new(()),
        };
        spi.init_regs();
        spi
    }

    /// The SSP input clock this controller was bound with.
    pub fn sspclk_hz(&self) -> u32 {
        self.sspclk_hz
    }

    fn init_regs(&self) {
        // Disable SSP
        let mut cr1 = self.read_u32(PL022_CR1);
        cr1 &= !PL022_CR1_SSE;
        self.write_u32(PL022_CR1, cr1);

        // Set 8-bit data, Motorola SPI frame format
        let mut cr0 = self.read_u32(PL022_CR0);
        cr0 = (cr0 & !0x3F) | PL022_CR0_DSS_8BIT;
        self.write_u32(PL022_CR0, cr0);

        // Mask all interrupts
        self.write_u32(PL022_IMSC, 0);

        // Enable SSP
        cr1 |= PL022_CR1_SSE;
        self.write_u32(PL022_CR1, cr1);
    }

    fn read_u32(&self, off: u64) -> u32 {
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { narf_arch::mmio::read32(self.base_va + off) }
    }

    fn write_u32(&self, off: u64, val: u32) {
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { narf_arch::mmio::write32(self.base_va + off, val) }
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

    fn set_freq(&self, hz: u32) -> Result<(), SpiError> {
        let _guard = self.state.lock();
        let (cpsdvr, scr) = divisor_for(self.sspclk_hz, hz).ok_or(SpiError::FrequencyOutOfRange)?;
        // SSP must be disabled while CPSR / CR0.SCR change.
        let cr1 = self.read_u32(PL022_CR1);
        self.write_u32(PL022_CR1, cr1 & !PL022_CR1_SSE);
        self.write_u32(PL022_CPSR, cpsdvr as u32);
        let mut cr0 = self.read_u32(PL022_CR0);
        cr0 = (cr0 & !(0xFF << 8)) | ((scr as u32) << 8);
        self.write_u32(PL022_CR0, cr0);
        self.write_u32(PL022_CR1, cr1);
        Ok(())
    }

    fn set_cs(&self, _cs: u8) -> Result<(), SpiError> {
        // PL022 CS is typically managed via GPIOs in Linux.
        // We will leave this as a no-op or stub for now.
        Ok(())
    }
}

/// Pick the (CPSDVSR, SCR) pair generating the highest SCK
/// ≤ `hz` from `sspclk`: SCK = SSPCLK / (CPSDVSR × (1 + SCR)),
/// CPSDVSR even in 2..=254, SCR in 0..=255. `None` when `hz` is
/// above SSPCLK/2, below SSPCLK/(254×256), or either input is 0.
/// Pure — the divisor math is host-assertable without hardware.
pub fn divisor_for(sspclk: u32, hz: u32) -> Option<(u8, u8)> {
    if sspclk == 0 || hz == 0 || hz > sspclk / 2 {
        return None;
    }
    let mut best: Option<(u8, u8, u32)> = None;
    let mut cpsdvr: u32 = 2;
    while cpsdvr <= 254 {
        // Smallest (1 + SCR) that brings SCK to ≤ hz at this
        // prescaler; skip the prescaler if even SCR=255 can't.
        let denom = cpsdvr * hz;
        let one_plus_scr = sspclk.div_ceil(denom);
        if one_plus_scr <= 256 {
            let actual = sspclk / (cpsdvr * one_plus_scr);
            if actual <= hz && best.is_none_or(|(_, _, b)| actual > b) {
                best = Some((cpsdvr as u8, (one_plus_scr - 1) as u8, actual));
            }
        }
        cpsdvr += 2;
    }
    best.map(|(c, s, _)| (c, s))
}

/// DT probe (`arm,pl022`): map the window, resolve SSPCLK from
/// the node's `clocks` phandle (fallback [`SSPCLK_FALLBACK_HZ`]),
/// register into the shared bus registry, publish DT children.
pub(crate) fn probe_dt(
    dev: narf_bus::BusDevice,
    _cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> Result<(), narf_bus::ProbeError> {
    use narf_bus::ProbeError;
    use narf_memory::ioremap::{ioremap, MmioAttrs};
    let narf_bus::BusKind::Platform(rec) = dev.kind else {
        return Err(ProbeError::NotForThisDriver);
    };
    let win = rec.reg_windows().first().ok_or(ProbeError::BadDevice)?;
    let sspclk_hz = crate::dt::controller_clock_hz(&rec).unwrap_or(SSPCLK_FALLBACK_HZ);
    // SAFETY: the window is the device's DT reg window; ioremap
    // maps it device-nongathering for the binding's lifetime (the
    // mapping rides inside the registered controller).
    let mapping = unsafe { ioremap(win.base.raw(), win.len.max(0x1000), MmioAttrs::Device) }
        .map_err(|_| ProbeError::Other("pl022: ioremap of the DT reg window failed"))?;
    let name = alloc::format!("pl022@{:#x}", win.base.raw());
    // SAFETY: the ioremap covers the PL022 register block.
    let spi = unsafe { Pl022Spi::new_mapped(name, mapping, sspclk_hz) };
    let bus = crate::registry::register_unique(alloc::sync::Arc::new(spi));
    crate::dt::publish_and_bind(&rec, &bus);
    Ok(())
}

/// Probe for PL022 SPI controllers on non-DT paths. DT machines
/// bind through [`probe_dt`]; there is no ACPI/PCI enumeration
/// story for this cell, so this stays empty.
pub fn probe_all() -> usize {
    0
}
