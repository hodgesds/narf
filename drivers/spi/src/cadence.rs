//! Cadence SPI controller driver.
//!
//! Provides support for the Cadence SPI controller found in many ARM
//! and Xilinx Zynq SoCs.
//!
//! References: `linux/drivers/spi/spi-cadence.c`
//!
//! DT programme step 5: the controller binds from devicetree
//! (`cdns,spi-r1p6`, see [`probe_dt`]) over an ioremap'd window
//! and registers into the crate's shared bus registry. The
//! reference clock resolves at probe time from the node's
//! `clocks` phandle (bus spec §3.1); without one the binding
//! falls back to [`REF_CLK_FALLBACK_HZ`]. `set_freq` programs
//! the CR baud-divisor field from that clock via [`divisor_for`].

extern crate alloc;

use alloc::string::String;

use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::ioremap::IoMapping;
use narf_memory::PhysAddr;

use crate::{SpiBus, SpiError, SpiMode};

// ── Register offsets ───────────────────────────────────────────────

const CDNS_SPI_CR: u64 = 0x00; // Configuration Register
const CDNS_SPI_ISR: u64 = 0x04; // Interrupt Status Register
const CDNS_SPI_ER: u64 = 0x14; // Enable/Disable Register
const CDNS_SPI_TXD: u64 = 0x1C; // Data Transmit Register
const CDNS_SPI_RXD: u64 = 0x20; // Data Receive Register

const CDNS_SPI_CR_MANSTRT: u32 = 0x0001_0000;
const CDNS_SPI_CR_CPHA: u32 = 0x0000_0004;
const CDNS_SPI_CR_CPOL: u32 = 0x0000_0002;
const CDNS_SPI_CR_SSCTRL: u32 = 0x0000_3C00;
const CDNS_SPI_CR_MSTREN: u32 = 0x0000_0001;
const CDNS_SPI_CR_MANSTRTEN: u32 = 0x0000_8000;
const CDNS_SPI_CR_SSFORCE: u32 = 0x0000_4000;

const CDNS_SPI_ER_ENABLE: u32 = 0x0000_0001;
const CDNS_SPI_ER_DISABLE: u32 = 0x0000_0000;

const CDNS_SPI_IXR_TXOW: u32 = 0x0000_0004; // TX FIFO Overwater
const CDNS_SPI_IXR_RXNEMTY: u32 = 0x0000_0010; // RX FIFO Not Empty

/// CR baud-rate divisor field (bits [5:3]): SCK = REF / divisor,
/// field value i selects `BAUD_DIVISORS[i]`.
const CDNS_SPI_CR_BAUD_MASK: u32 = 0x38;
const BAUD_DIVISORS: [u32; 7] = [4, 8, 16, 32, 64, 128, 256];

/// Reference-clock fallback when the DT node carries no usable
/// `clocks` phandle: the 100 MHz class the Zynq PS SPI reference
/// commonly runs at. A placeholder constant consumed per bus
/// spec §3.1 until the clock framework (#1052) lands — boards
/// whose reference differs must describe it in DT.
pub const REF_CLK_FALLBACK_HZ: u32 = 100_000_000;

// ── Controller struct ──────────────────────────────────────────────

#[derive(Debug)]
pub struct CadenceSpi {
    name: String,
    /// Access base: the phys window itself in the legacy form,
    /// the ioremap VA in the DT-bound form.
    base_va: u64,
    /// Kept so the ioremap lives as long as the controller;
    /// `None` for the phys form.
    _mapping: Option<IoMapping>,
    /// Reference clock in Hz (0 = unknown; `set_freq` then
    /// refuses). Fixed at construction.
    ref_clk_hz: u32,
    state: IrqSafeSpinLock<()>,
}

impl CadenceSpi {
    pub fn new(name: String, mmio_base: PhysAddr) -> Self {
        let spi = Self {
            name,
            base_va: mmio_base.raw(),
            _mapping: None,
            ref_clk_hz: 0,
            state: IrqSafeSpinLock::new(()),
        };
        spi.init_regs();
        spi
    }

    /// Construct over an ioremap'd window with a known reference
    /// clock (the DT binding's form).
    ///
    /// # Safety
    /// `mapping` must cover the Cadence SPI register block (4 KiB).
    pub unsafe fn new_mapped(name: String, mapping: IoMapping, ref_clk_hz: u32) -> Self {
        let spi = Self {
            name,
            base_va: mapping.va(),
            _mapping: Some(mapping),
            ref_clk_hz,
            state: IrqSafeSpinLock::new(()),
        };
        spi.init_regs();
        spi
    }

    /// The reference clock this controller was bound with.
    pub fn ref_clk_hz(&self) -> u32 {
        self.ref_clk_hz
    }

    fn init_regs(&self) {
        // Initial reset
        self.write_u32(CDNS_SPI_ER, CDNS_SPI_ER_DISABLE);

        let mut cr = self.read_u32(CDNS_SPI_CR);
        cr |= CDNS_SPI_CR_MSTREN | CDNS_SPI_CR_SSFORCE | CDNS_SPI_CR_MANSTRTEN;
        self.write_u32(CDNS_SPI_CR, cr);

        self.write_u32(CDNS_SPI_ER, CDNS_SPI_ER_ENABLE);
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

    fn set_freq(&self, hz: u32) -> Result<(), SpiError> {
        let _guard = self.state.lock();
        let field = divisor_for(self.ref_clk_hz, hz).ok_or(SpiError::FrequencyOutOfRange)?;
        let mut cr = self.read_u32(CDNS_SPI_CR);
        cr = (cr & !CDNS_SPI_CR_BAUD_MASK) | ((field as u32) << 3);
        self.write_u32(CDNS_SPI_CR, cr);
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

/// Pick the CR baud-divisor field value generating the highest
/// SCK ≤ `hz` from `ref_clk` (SCK = REF / divisor; field values
/// index [`BAUD_DIVISORS`]). `None` when `hz` exceeds REF/4, is
/// below REF/256, or either input is 0. Pure — host-assertable.
pub fn divisor_for(ref_clk: u32, hz: u32) -> Option<u8> {
    if ref_clk == 0 || hz == 0 || hz > ref_clk / BAUD_DIVISORS[0] {
        return None;
    }
    for (i, d) in BAUD_DIVISORS.iter().enumerate() {
        if ref_clk / d <= hz {
            return Some(i as u8);
        }
    }
    None
}

/// DT probe (`cdns,spi-r1p6`): map the window, resolve the
/// reference clock from the node's `clocks` phandle (fallback
/// [`REF_CLK_FALLBACK_HZ`]), register into the shared bus
/// registry, publish DT children.
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
    let ref_clk_hz = crate::dt::controller_clock_hz(&rec).unwrap_or(REF_CLK_FALLBACK_HZ);
    // SAFETY: the window is the device's DT reg window; ioremap
    // maps it device-nongathering for the binding's lifetime (the
    // mapping rides inside the registered controller).
    let mapping = unsafe { ioremap(win.base.raw(), win.len.max(0x1000), MmioAttrs::Device) }
        .map_err(|_| ProbeError::Other("cadence-spi: ioremap of the DT reg window failed"))?;
    let name = alloc::format!("cdns-spi@{:#x}", win.base.raw());
    // SAFETY: the ioremap covers the Cadence register block.
    let spi = unsafe { CadenceSpi::new_mapped(name, mapping, ref_clk_hz) };
    let bus = crate::registry::register_unique(alloc::sync::Arc::new(spi));
    crate::dt::publish_children(&rec, bus.name());
    Ok(())
}

/// Probe for Cadence SPI controllers on non-DT paths. DT machines
/// bind through [`probe_dt`]; there is no ACPI/PCI enumeration
/// story for this cell, so this stays empty.
pub fn probe_all() -> usize {
    0
}
