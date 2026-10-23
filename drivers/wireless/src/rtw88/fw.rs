//! Raw MMIO alone cannot establish firmware DMA ownership. The RTL8822CE
//! probe retains a private parsed-section/beacon-DMA owner; this legacy helper
//! stays unsupported because BAR2 is only the control-register aperture.

use narf_bus::MmioRegion;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FwError {
    /// The caller supplied no retained native DMA/ring/reset ownership.
    Unsupported,
}

/// Reject firmware loading before registry access or any MMIO. Detection
/// does not invoke this helper; its private native owner supplies DMA authority.
pub fn download_firmware(_registers: &MmioRegion, _did: u16) -> Result<(), FwError> {
    Err(FwError::Unsupported)
}
