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
//! LPSS_CS_CONTROL       varies by platform (reg_cs_ctrl from lpss_platforms[])
//! ```
//!
//! # Stage-0 status
//!
//! Discovery and MMIO mapping are implemented. `transfer()`,
//! `set_mode()`, `set_freq()`, `set_cs()` return `BadHardware` as a
//! well-defined stub. Stage-1 will port the SSP FIFO state machine.
//!
//! Deferred: DMA mode, slave mode, SoundWire-over-SPI.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_memory::PhysAddr;

use crate::{SpiBus, SpiError, SpiMode};

// ── PCI device table ───────────────────────────────────────────────
//
// Vendor 0x8086 = Intel. Device IDs from Linux spi-intel-pci.c and
// spi-pxa2xx-pci.c.

/// Intel PCI vendor ID.
pub const INTEL_PCI_VENDOR: u16 = 0x8086;

/// Intel LPSS SPI PCI device IDs. Each entry is (device_id, description).
/// Source: Linux drivers/spi/spi-intel-pci.c intel_spi_pci_ids[].
pub const INTEL_LPSS_SPI_PCI_DEVICES: &[(u16, &str)] = &[
    // Skylake PCH SPI (SPT-LP)
    (0x9D24, "Skylake-LP PCH SPI"),
    (0x9DA4, "Skylake/Kaby Lake PCH-LP SPI"),
    // Tiger Lake
    (0xA0A4, "Tiger Lake PCH SPI"),
    // Alder Lake
    (0x7AA4, "Alder Lake PCH SPI"),
    // Raptor Lake
    (0x51A4, "Raptor Lake PCH SPI"),
    // Meteor Lake
    (0x7E23, "Meteor Lake PCH SPI"),
    // Cannon Lake / Ice Lake
    (0x02A4, "Ice Lake PCH SPI"),
    (0x34A4, "Ice Lake PCH SPI"),
    // Comet Lake
    (0x06A4, "Comet Lake PCH SPI"),
    // Apollo Lake (BXT)
    (0x19E0, "Apollo Lake SPI"),
    // Gemini Lake
    (0x31A4, "Gemini Lake SPI"),
    // LPSS SSP (Lynx Point / Sunrise Point, spi-pxa2xx-pci.c)
    (0x9C65, "Lynx Point LPSS SSP0"),
    (0x9C66, "Lynx Point LPSS SSP1"),
    (0x9CE5, "Wildcat Point LPSS SSP0"),
    (0x9CE6, "Wildcat Point LPSS SSP1"),
];

// ── ACPI HIDs ──────────────────────────────────────────────────────
//
// From Linux spi-pxa2xx-platform.c pxa2xx_spi_acpi_match[].

const INTEL_LPSS_SPI_ACPI_HIDS: &[&str] = &[
    "80860F0E", // Bay Trail / Baytrail
    "8086228E", // Braswell
    "INT33C0",  // Haswell (old HID)
    "INT33C1",  // Haswell (old HID)
    "INT3430",  // Broadwell / Skylake
    "INT3431",  // Broadwell / Skylake
];

// ── SSP register offsets ───────────────────────────────────────────
//
// From Linux spi-pxa2xx.h (included via spi-pxa2xx.c).

const SSCR0: u64 = 0x00;
const SSCR1: u64 = 0x04;
#[allow(dead_code)]
const SSSR: u64 = 0x08;
#[allow(dead_code)]
const SSDR: u64 = 0x10;

// ── SSCR0 bit definitions ──────────────────────────────────────────
const SSCR0_SSE: u32 = 1 << 7;         // SSP enable
const SSCR0_FRF_SPI: u32 = 0b00 << 4; // Motorola SPI frame format
const SSCR0_DSS_8BIT: u32 = 0b0111;   // Data size select: 8 bits

// ── SSCR1 bit definitions ──────────────────────────────────────────
const SSCR1_SPO: u32 = 1 << 3; // Clock polarity
const SSCR1_SPH: u32 = 1 << 4; // Clock phase (CPHA)

// ── SSSR bit definitions ───────────────────────────────────────────
#[allow(dead_code)]
const SSSR_TNF: u32 = 1 << 2;  // TX FIFO not full — used by Stage-1 FIFO driver
#[allow(dead_code)]
const SSSR_RNE: u32 = 1 << 3;  // RX FIFO not empty — used by Stage-1 FIFO driver
#[allow(dead_code)]
const SSSR_BSY: u32 = 1 << 4;  // SSP busy — used by Stage-1 FIFO driver

// ── FIFO parameters ────────────────────────────────────────────────
//
// The SSP FIFO is 16 entries deep (16 × 32 bits) across all LPSS
// variants. An 8-bit transfer uses 8 bits per FIFO entry.
pub const INTEL_SSP_FIFO_DEPTH: usize = 16;

// ── Busy-wait budget ───────────────────────────────────────────────
#[allow(dead_code)]
const BUSY_WAIT_POLLS: u32 = 100_000; // used by Stage-1 FIFO driver

// ── Driver struct ──────────────────────────────────────────────────

/// One Intel LPSS SPI controller instance.
pub struct IntelLpssSpi {
    name: String,
    mmio_base: PhysAddr,
    mmio_len: u64,
    /// Cached mode.
    mode: AtomicU32,
    /// Cached chip-select.
    cs: AtomicU32,
    /// Cached frequency.
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
    /// Construct a controller. Used by `probe_all` and smoke tests.
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

    // ── MMIO accessors ─────────────────────────────────────────────

    #[inline]
    unsafe fn read32(&self, off: u64) -> u32 {
        debug_assert!(off + 4 <= self.mmio_len);
        // SAFETY: caller serialises.
        unsafe { narf_arch::mmio::read32(self.mmio_base.raw() + off) }
    }

    #[inline]
    unsafe fn write32(&self, off: u64, val: u32) {
        debug_assert!(off + 4 <= self.mmio_len);
        // SAFETY: same.
        unsafe { narf_arch::mmio::write32(self.mmio_base.raw() + off, val) }
    }

    // ── SSP control helpers ────────────────────────────────────────

    /// Enable the SSP (set SSCR0.SSE).
    unsafe fn enable_ssp(&self) {
        // SAFETY: caller serialises.
        let cr0 = unsafe { self.read32(SSCR0) };
        unsafe { self.write32(SSCR0, cr0 | SSCR0_SSE) };
    }

    /// Disable the SSP.
    unsafe fn disable_ssp(&self) {
        // SAFETY: caller serialises.
        let cr0 = unsafe { self.read32(SSCR0) };
        unsafe { self.write32(SSCR0, cr0 & !SSCR0_SSE) };
    }

    /// Apply the cached CPOL/CPHA mode bits to SSCR1. Must be called
    /// with the SSP disabled; SSCR1.SPO and SPH are writable only
    /// when SSE=0 on most LPSS variants.
    unsafe fn apply_mode_bits(&self) {
        let mode = self.mode.load(Ordering::Relaxed);
        let cpol = (mode & 0b10) != 0;
        let cpha = (mode & 0b01) != 0;
        // SAFETY: caller ensures SSP is disabled.
        let cr1 = unsafe { self.read32(SSCR1) };
        let mut new = cr1 & !(SSCR1_SPO | SSCR1_SPH);
        if cpol {
            new |= SSCR1_SPO;
        }
        if cpha {
            new |= SSCR1_SPH;
        }
        unsafe { self.write32(SSCR1, new) };
    }

    /// Initialize the SSP for 8-bit SPI master mode.
    pub fn init(&self) -> Result<(), SpiError> {
        // SAFETY: single-threaded probe path; no concurrent transfers.
        unsafe {
            self.disable_ssp();
            // 8-bit, Motorola SPI frame, SCR=0 (divide-by-1).
            self.write32(SSCR0, SSCR0_FRF_SPI | SSCR0_DSS_8BIT);
            self.apply_mode_bits();
            self.enable_ssp();
        }
        Ok(())
    }

    /// Poll SSSR.BSY until the SSP is idle.
    /// Reserved for Stage-1 FIFO driver; not yet called by the Stage-0 stub.
    #[allow(dead_code)]
    fn busy_wait(&self) -> Result<(), SpiError> {
        for _ in 0..BUSY_WAIT_POLLS {
            // SAFETY: bus lock held (or probe path).
            if unsafe { self.read32(SSSR) } & SSSR_BSY == 0 {
                return Ok(());
            }
        }
        Err(SpiError::Timeout)
    }
}

impl SpiBus for IntelLpssSpi {
    /// Stage-0 stub. Returns `BadHardware` until Stage-1 ports the
    /// FIFO state machine. Hard-cutover: this stub is replaced in
    /// full, not patched behind a flag.
    fn transfer(&self, _tx: &[u8], _rx: &mut [u8]) -> Result<(), SpiError> {
        Err(SpiError::BadHardware)
    }

    fn transfer_full_duplex(&self, _tx: &mut [u8], _rx: &mut [u8]) -> Result<(), SpiError> {
        Err(SpiError::BadHardware)
    }

    fn set_mode(&self, mode: SpiMode) -> Result<(), SpiError> {
        self.mode.store(mode as u32, Ordering::Relaxed);
        // SAFETY: probe path or bus lock — applying mode bits requires
        // toggling SSE; defer to next init() call.
        unsafe {
            self.disable_ssp();
            self.apply_mode_bits();
            self.enable_ssp();
        }
        Ok(())
    }

    fn set_freq(&self, hz: u32) -> Result<(), SpiError> {
        // Stage-0: store for reference; SCR clock divider programming
        // deferred to Stage-1 when the full FIFO driver lands.
        if hz == 0 {
            return Err(SpiError::FrequencyOutOfRange);
        }
        self.speed_hz.store(hz, Ordering::Relaxed);
        Ok(())
    }

    fn set_cs(&self, cs: u8) -> Result<(), SpiError> {
        // LPSS CS control is via the LPSS private register block.
        // Stage-0: validate range (≤3 CS lines on LPSS), cache.
        if cs > 3 {
            return Err(SpiError::InvalidCs);
        }
        self.cs.store(cs as u32, Ordering::Relaxed);
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ── Discovery ──────────────────────────────────────────────────────

/// Walk the AML namespace for Intel LPSS SPI ACPI HIDs, decode _CRS,
/// and register each controller. Returns the count registered.
pub fn probe_all() -> usize {
    use core::fmt::Write;
    let mut count = 0usize;
    for &hid in INTEL_LPSS_SPI_ACPI_HIDS {
        for node in narf_aml::find_all_devices_by_hid(hid) {
            let _ = writeln!(
                narf_console::Writer,
                "  intel-lpss-spi: probing {} (HID={})",
                node.path, hid
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
    crate::registry::register_unique(drv);
    let _ = writeln!(
        narf_console::Writer,
        "  intel-lpss-spi: {} registered mmio={:#x}+{:#x}",
        path, base, len
    );
    Some(())
}

/// Test-only: list ACPI HIDs we recognise.
#[doc(hidden)]
pub fn recognised_hids() -> &'static [&'static str] {
    INTEL_LPSS_SPI_ACPI_HIDS
}

/// Test-only: list PCI (vendor, device) pairs we recognise.
#[doc(hidden)]
pub fn recognised_pci_ids() -> &'static [(u16, &'static str)] {
    INTEL_LPSS_SPI_PCI_DEVICES
}

/// Test-only: construct a driver instance against a synthetic MMIO
/// buffer without going through ACPI discovery.
#[doc(hidden)]
pub fn __new_for_test(name: String, mmio_base: PhysAddr, mmio_len: u64) -> IntelLpssSpi {
    IntelLpssSpi::new(name, mmio_base, mmio_len)
}
