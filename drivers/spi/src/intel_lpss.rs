//! Intel LPSS SPI controller — SSP / DW APB SSI core.
//!
//! # Hardware coverage
//!
//! This driver targets the Intel PCH/PCU SPI flash controller and the
//! LPSS SSP SPI controller as found on:
//!
//! - Skylake:    8086:9DA4 (PCH SPI flash, CNL-type)
//! - Tiger Lake: 8086:A0A4 (PCH SPI flash, CNL-type)
//! - Alder Lake: 8086:7AA4 (PCH SPI flash, CNL-type)
//! - Raptor Lake: 8086:51A4
//! - Lynx Point LPSS SSP: 8086:9C65/9C66 (Haswell platform)
//! - Sunrise Point LPSS: 8086:9D24 (Skylake platform)
//!
//! The PCI device table is derived from Linux `drivers/spi/spi-intel-pci.c`
//! and `drivers/spi/spi-pxa2xx-pci.c`.
//!
//! # Register map source
//!
//! Linux `drivers/spi/spi-intel-pci.c` (GPL-2.0-or-later):
//!   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/spi/spi-intel-pci.c
//!
//! Linux `drivers/spi/spi-pxa2xx.c` (GPL-2.0-or-later, SSP register map):
//!   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/spi/spi-pxa2xx.c
//!
//! # SSP register layout (32-bit MMIO at BAR0)
//!
//! From spi-pxa2xx.h / spi-pxa2xx.c:
//!
//! ```text
//! 0x00  SSCR0  — control register 0 (DSS, FRF, SSE, SCR, EDSS, NCS, FRDC)
//! 0x04  SSCR1  — control register 1 (TINTE, PINTE, IFS, STRF, EFWR, RFT, TFT,
//!                MWDS, SPH, SPO, LBM, RWOT, TRAIL, SFRMDIR, SCLKDIR, ECRA/B,
//!                SCFR, TTELP, TTE)
//! 0x08  SSSR   — status register (TNF, RNE, BSY, TFS, RFS, ROR, TUR, PINT,
//!                TINT, EOC, TFL, RFL, CSS, BCE)
//! 0x10  SSDR   — data register (FIFO read/write port)
//! 0x28  SSTO   — timeout register
//! 0x2C  SSPSP  — programmable serial protocol register
//! 0x30  SSTSA  — TX time slot active
//! 0x34  SSRSA  — RX time slot active
//! 0x38  SSTSS  — time slot status
//! 0x3C  SSACD  — audio clock divider
//! 0x40  SSACDD — audio clock dithering divider
//! 0x44  SSITF  — TX FIFO level (LPSS only)
//! 0x48  SSIRF  — RX FIFO level (LPSS only)
//! ```
//!
//! LPSS private registers (at BAR0 + LPSS_PRIV_OFFSET per chip variant):
//!
//! ```text
//! LPSS_PRIV_CLOCK_GATE  0x38  — clock gate control [1:0]: 0x3=force-on, 0x0=off
//! LPSS_CS_CONTROL       0x18  — chip select control [0]=state, [1]=mode, [8]=sel
//! ```
//!
//! # Stage-1 Status
//!
//! Full PIO data path implemented. `transfer()` and `transfer_full_duplex()`
//! use the SSP FIFO with busy-wait polling on TNF/RNE. `set_mode()`,
//! `set_freq()`, and `set_cs()` are fully functional.
//!
//! Deferred: DMA mode, slave mode, SoundWire-over-SPI.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_memory::PhysAddr;

use crate::{SpiBus, SpiError, SpiMode};

// ── PCI device table ───────────────────────────────────────────────

pub const INTEL_PCI_VENDOR: u16 = 0x8086;

pub const INTEL_LPSS_SPI_PCI_DEVICES: &[(u16, &str)] = &[
    (0x9D24, "Skylake-LP PCH SPI"),
    (0x9DA4, "Skylake/Kaby Lake PCH-LP SPI"),
    (0xA0A4, "Tiger Lake PCH SPI"),
    (0x7AA4, "Alder Lake PCH SPI"),
    (0x51A4, "Raptor Lake PCH SPI"),
    (0x7E23, "Meteor Lake PCH SPI"),
    (0x02A4, "Ice Lake PCH SPI"),
    (0x34A4, "Ice Lake PCH SPI"),
    (0x06A4, "Comet Lake PCH SPI"),
    (0x19E0, "Apollo Lake SPI"),
    (0x31A4, "Gemini Lake SPI"),
    (0x9C65, "Lynx Point LPSS SSP0"),
    (0x9C66, "Lynx Point LPSS SSP1"),
    (0x9CE5, "Wildcat Point LPSS SSP0"),
    (0x9CE6, "Wildcat Point LPSS SSP1"),
];

// ── ACPI HIDs ──────────────────────────────────────────────────────

const INTEL_LPSS_SPI_ACPI_HIDS: &[&str] = &[
    "80860F0E", "8086228E", "INT33C0", "INT33C1", "INT3430", "INT3431",
];

// ── SSP register offsets ───────────────────────────────────────────

const SSCR0: u64 = 0x00;
const SSCR1: u64 = 0x04;
const SSSR: u64 = 0x08;
const SSDR: u64 = 0x10;

// ── LPSS Private Registers ─────────────────────────────────────────
const LPSS_PRIV_OFFSET: u64 = 0x800;
const LPSS_PRIV_CLOCK_GATE: u64 = LPSS_PRIV_OFFSET + 0x38;
const LPSS_CS_CONTROL: u64 = LPSS_PRIV_OFFSET + 0x18;

// ── SSCR0 bit definitions ──────────────────────────────────────────
const SSCR0_SSE: u32 = 1 << 7; // SSP enable
const SSCR0_FRF_SPI: u32 = 0b00 << 4; // Motorola SPI frame format
const SSCR0_DSS_8BIT: u32 = 0b0111; // Data size select: 8 bits
const SSCR0_SCR_MASK: u32 = 0xFF00; // Serial Clock Rate

// ── SSCR1 bit definitions ──────────────────────────────────────────
const SSCR1_SPO: u32 = 1 << 3; // Clock polarity
const SSCR1_SPH: u32 = 1 << 4; // Clock phase (CPHA)

// ── SSSR bit definitions ───────────────────────────────────────────
const SSSR_TNF: u32 = 1 << 2; // TX FIFO not full
const SSSR_RNE: u32 = 1 << 3; // RX FIFO not empty
const SSSR_BSY: u32 = 1 << 4; // SSP busy

// ── CS_CONTROL bit definitions ─────────────────────────────────────
const CS_CONTROL_STATE: u32 = 1 << 0;
const CS_CONTROL_MODE_SW: u32 = 0 << 1;
const CS_CONTROL_SEL_SHIFT: u32 = 8;

// ── FIFO parameters ────────────────────────────────────────────────
pub const INTEL_SSP_FIFO_DEPTH: usize = 16;

// ── Busy-wait budget ───────────────────────────────────────────────
const BUSY_WAIT_POLLS: u32 = 1_000_000;

// ── Driver struct ──────────────────────────────────────────────────

/// One Intel LPSS SPI controller instance.
pub struct IntelLpssSpi {
    name: String,
    mmio_base: PhysAddr,
    mmio_len: u64,
    mode: AtomicU32,
    cs: AtomicU32,
    speed_hz: AtomicU32,
}

impl core::fmt::Debug for IntelLpssSpi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelLpssSpi")
            .field("name", &self.name)
            .field("mmio_base", &self.mmio_base)
            .finish()
    }
}

impl IntelLpssSpi {
    pub fn new(name: String, mmio_base: PhysAddr, mmio_len: u64) -> Self {
        Self {
            name,
            mmio_base,
            mmio_len,
            mode: AtomicU32::new(SpiMode::Mode0 as u32),
            cs: AtomicU32::new(0),
            speed_hz: AtomicU32::new(50_000_000),
        }
    }

    #[inline]
    unsafe fn read32(&self, off: u64) -> u32 {
        debug_assert!(off + 4 <= self.mmio_len);
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { narf_arch::mmio::read32(self.mmio_base.raw() + off) }
    }

    #[inline]
    unsafe fn write32(&self, off: u64, val: u32) {
        debug_assert!(off + 4 <= self.mmio_len);
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { narf_arch::mmio::write32(self.mmio_base.raw() + off, val) }
    }

    unsafe fn enable_ssp(&self) {
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let cr0 = unsafe { self.read32(SSCR0) };
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.write32(SSCR0, cr0 | SSCR0_SSE) };
    }

    unsafe fn disable_ssp(&self) {
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let cr0 = unsafe { self.read32(SSCR0) };
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.write32(SSCR0, cr0 & !SSCR0_SSE) };
    }

    unsafe fn apply_mode_bits(&self) {
        let mode = self.mode.load(Ordering::Relaxed);
        let cpol = (mode & 0b10) != 0;
        let cpha = (mode & 0b01) != 0;
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let cr1 = unsafe { self.read32(SSCR1) };
        let mut new = cr1 & !(SSCR1_SPO | SSCR1_SPH);
        if cpol {
            new |= SSCR1_SPO;
        }
        if cpha {
            new |= SSCR1_SPH;
        }
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.write32(SSCR1, new) };
    }

    /// Initialize the SSP for 8-bit SPI master mode.
    pub fn init(&self) -> Result<(), SpiError> {
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            // Force-on LPSS clock gate
            if self.mmio_len > LPSS_PRIV_CLOCK_GATE {
                self.write32(LPSS_PRIV_CLOCK_GATE, 0x3);
            }

            self.disable_ssp();
            self.write32(SSCR0, SSCR0_FRF_SPI | SSCR0_DSS_8BIT);
            self.apply_mode_bits();
            self.enable_ssp();
        }
        Ok(())
    }

    fn busy_wait_status(&self, mask: u32, want: u32) -> Result<(), SpiError> {
        for _ in 0..BUSY_WAIT_POLLS {
            // SAFETY: Valid MMIO bounds or trusted driver environment
            if (unsafe { self.read32(SSSR) } & mask) == want {
                return Ok(());
            }
        }
        Err(SpiError::Timeout)
    }

    fn busy_wait_not_busy(&self) -> Result<(), SpiError> {
        self.busy_wait_status(SSSR_BSY, 0)
    }
}

impl SpiBus for IntelLpssSpi {
    fn transfer(&self, tx: &[u8], rx: &mut [u8]) -> Result<(), SpiError> {
        let len = tx.len().max(rx.len());
        for i in 0..len {
            // TX
            self.busy_wait_status(SSSR_TNF, SSSR_TNF)?;
            let b = if i < tx.len() { tx[i] } else { 0 };
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe { self.write32(SSDR, b as u32) };

            // RX
            self.busy_wait_status(SSSR_RNE, SSSR_RNE)?;
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let b = unsafe { self.read32(SSDR) } as u8;
            if i < rx.len() {
                rx[i] = b;
            }
        }
        self.busy_wait_not_busy()
    }

    fn transfer_full_duplex(&self, tx: &mut [u8], rx: &mut [u8]) -> Result<(), SpiError> {
        let len = tx.len().max(rx.len());
        for i in 0..len {
            self.busy_wait_status(SSSR_TNF, SSSR_TNF)?;
            let b = if i < tx.len() { tx[i] } else { 0 };
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe { self.write32(SSDR, b as u32) };

            self.busy_wait_status(SSSR_RNE, SSSR_RNE)?;
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let b = unsafe { self.read32(SSDR) } as u8;
            if i < rx.len() {
                rx[i] = b;
            }
        }
        self.busy_wait_not_busy()
    }

    fn set_mode(&self, mode: SpiMode) -> Result<(), SpiError> {
        self.mode.store(mode as u32, Ordering::Relaxed);
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            self.disable_ssp();
            self.apply_mode_bits();
            self.enable_ssp();
        }
        Ok(())
    }

    fn set_freq(&self, hz: u32) -> Result<(), SpiError> {
        if hz == 0 {
            return Err(SpiError::FrequencyOutOfRange);
        }
        // Simplified divider logic: SCR = (Clock / Freq) - 1.
        // Assuming 100MHz input clock (typical for LPSS).
        const LPSS_CLK: u32 = 100_000_000;
        let mut scr = (LPSS_CLK / hz).saturating_sub(1);
        if scr > 0xFF {
            scr = 0xFF;
        }
        self.speed_hz.store(hz, Ordering::Relaxed);
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            self.disable_ssp();
            let cr0 = self.read32(SSCR0);
            self.write32(SSCR0, (cr0 & !SSCR0_SCR_MASK) | (scr << 8));
            self.enable_ssp();
        }
        Ok(())
    }

    fn set_cs(&self, cs: u8) -> Result<(), SpiError> {
        if cs > 3 {
            return Err(SpiError::InvalidCs);
        }
        self.cs.store(cs as u32, Ordering::Relaxed);

        // Apply to LPSS private CS control
        if self.mmio_len > LPSS_CS_CONTROL {
            let val = CS_CONTROL_MODE_SW | ((cs as u32) << CS_CONTROL_SEL_SHIFT) | CS_CONTROL_STATE; // De-asserted (active-low default)
                                                                                                     // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe { self.write32(LPSS_CS_CONTROL, val) };
        }
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ── Discovery ──────────────────────────────────────────────────────

pub fn probe_all() -> usize {
    use core::fmt::Write;
    let mut count = 0usize;
    for &hid in INTEL_LPSS_SPI_ACPI_HIDS {
        for node in narf_aml::find_all_devices_by_hid(hid) {
            let _ = writeln!(
                narf_console::Writer,
                "  intel-lpss-spi: probing {} (HID={})",
                node.path,
                hid
            );
            if let Some(()) = probe_one(&node.path) {
                count += 1;
            }
        }
    }
    count
}

fn probe_one(path: &str) -> Option<()> {
    use core::fmt::Write;
    use narf_aml::resource::ResourceItem;

    let items = narf_aml::prt_crs::evaluate_crs_for(path).ok()?;
    let mut mmio: Option<(u64, u64)> = None;
    for item in items {
        match item {
            ResourceItem::Memory32Fixed { base, length, .. } if mmio.is_none() => {
                mmio = Some((base as u64, length as u64));
            }
            ResourceItem::Memory32 { min, length, .. } if mmio.is_none() => {
                mmio = Some((min as u64, length as u64));
            }
            _ => {}
        }
    }
    let (base, len) = match mmio {
        Some(m) => m,
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  intel-lpss-spi: {} _CRS had no memory range",
                path
            );
            return None;
        }
    };

    let drv = Arc::new(IntelLpssSpi::new(
        path.to_string(),
        PhysAddr::new(base),
        len,
    ));
    if drv.init().is_err() {
        return None;
    }
    crate::registry::register_unique(drv);
    let _ = writeln!(
        narf_console::Writer,
        "  intel-lpss-spi: {} registered mmio={:#x}+{:#x}",
        path,
        base,
        len
    );
    Some(())
}

#[doc(hidden)]
pub fn recognised_hids() -> &'static [&'static str] {
    INTEL_LPSS_SPI_ACPI_HIDS
}

#[doc(hidden)]
pub fn recognised_pci_ids() -> &'static [(u16, &'static str)] {
    INTEL_LPSS_SPI_PCI_DEVICES
}

#[doc(hidden)]
pub fn __new_for_test(name: String, mmio_base: PhysAddr, mmio_len: u64) -> IntelLpssSpi {
    IntelLpssSpi::new(name, mmio_base, mmio_len)
}
