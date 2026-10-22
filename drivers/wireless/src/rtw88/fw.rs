//! Firmware loading is unavailable until a parsed section loader and PCIe
//! reserved-page DMA transport exist. Linux `rtw88/{fw,mac,pci}.c` sends
//! firmware through that transport; BAR2 is the control-register aperture.

use narf_bus::MmioRegion;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FwError {
    /// Firmware transport and per-chip loader lifecycle are not implemented.
    Unsupported,
}

/// Reject firmware loading before registry access or any MMIO. Detection
/// does not invoke this helper and never reports firmware-ready hardware.
pub fn download_firmware(_registers: &MmioRegion, _did: u16) -> Result<(), FwError> {
    Err(FwError::Unsupported)
}
