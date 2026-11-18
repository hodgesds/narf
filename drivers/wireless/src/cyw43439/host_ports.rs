// SPDX-License-Identifier: GPL-2.0-or-later
//! Additional CYW43439 host candidates. Discovery grants no radio authority.
//! gSPI uses the source-grounded whole-CS protocol in `gspi_port`; legacy
//! SpiBus transfer/set_cs cannot satisfy its exclusive/shared-pad contract.
//! Platform SDHCI remains dependent on a real platform host/aperture owner.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use narf_drivers_spi::{registry, SpiBus, SpiError, SpiMode};

#[path = "gspi_port.rs"]
pub(super) mod gspi_port;
pub use gspi_port::GspiTransport;

/// The kind of host port a CYW43439 can sit behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPortKind {
    /// The retained profile: PCI SDHCI via `narf-drivers-sdio`.
    PciSdhci,
    /// A non-PCI SDHCI controller at an explicit MMIO base.
    PlatformSdhci,
    /// A gSPI link over a registered SPI bus.
    SpiGspi,
}

/// A host port for a CYW43439, identified by the explicit host handle
/// the platform owner supplies. Nothing here is inferred from a chip
/// MANFID or a firmware filename.
#[derive(Debug, Clone)]
pub enum HostPort {
    /// The retained PCI SDHCI profile (see [`super::bootstrap`]).
    PciSdhci,
    /// A non-PCI SDHCI controller. Described, but not openable until
    /// `drivers/sdio` gains a platform MMIO aperture (see the module
    /// docs); `is_available()` is false for this kind.
    PlatformSdhci {
        /// Physical MMIO base of the SDHCI register aperture.
        mmio_base: u64,
    },
    /// A gSPI link over an already-registered SPI bus.
    SpiGspi {
        /// The bus controller, from `narf_drivers_spi::registry`.
        bus: Arc<dyn SpiBus>,
        /// Chip-select index on that bus.
        cs: u8,
    },
}

/// Errors opening or describing a host port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortError {
    /// The port is not a gSPI port.
    NotGspi,
    /// The port kind cannot be opened yet (platform SDHCI aperture).
    PlatformApertureUnavailable,
    /// The controller has no exclusive whole-transaction implementation.
    TransactionUnavailable,
    /// The actual controller owner refused a second device claim.
    BusClaimed,
    /// The SPI bus reported an error.
    Spi(SpiError),
}

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortError::NotGspi => f.write_str("host port is not a gSPI port"),
            PortError::PlatformApertureUnavailable => {
                f.write_str("platform SDHCI aperture unavailable")
            }
            PortError::TransactionUnavailable => f.write_str("whole-CS SPI session unavailable"),
            PortError::BusClaimed => f.write_str("SPI device already claimed"),
            PortError::Spi(_) => f.write_str("SPI bus error"),
        }
    }
}

impl HostPort {
    /// The kind of this port.
    pub fn kind(&self) -> HostPortKind {
        match self {
            HostPort::PciSdhci => HostPortKind::PciSdhci,
            HostPort::PlatformSdhci { .. } => HostPortKind::PlatformSdhci,
            HostPort::SpiGspi { .. } => HostPortKind::SpiGspi,
        }
    }

    /// Whether the port has a native attachment producer. Described SPI and
    /// platform candidates do not establish a selected, current native owner.
    /// A diagnostic gSPI protocol session may still be attempted explicitly.
    pub fn is_available(&self) -> bool {
        matches!(self, HostPort::PciSdhci)
    }

    /// Open the gSPI transport for a `SpiGspi` port, configuring the
    /// bus mode and frequency from the caller-supplied platform facts.
    /// Any other kind returns `PortError::NotGspi`.
    pub fn open_gspi(&self, mode: SpiMode, freq_hz: u32) -> Result<GspiTransport, PortError> {
        match self {
            HostPort::SpiGspi { bus, cs } => GspiTransport::new(bus.clone(), *cs, mode, freq_hz),
            HostPort::PciSdhci | HostPort::PlatformSdhci { .. } => Err(PortError::NotGspi),
        }
    }
}

/// Candidate gSPI ports: every SPI bus registered with
/// `narf_drivers_spi::registry`. These are candidates only — a bus
/// being registered says nothing about a CYW43439 being attached to
/// it. Presence is proven by [`GspiTransport::probe_link`] plus chip
/// identification through the loader, never by this list.
pub fn discover_spi_ports() -> Vec<Arc<dyn SpiBus>> {
    registry::list()
}
