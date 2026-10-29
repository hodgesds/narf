//! Compatibility surface for the retired generic ACP scaffold.
//!
//! Physical devices are registered through `acp63`, using Linux's
//! snd_pci_ps register map and revision/firmware checks. The historical
//! I2S model and its register constants were excised with their last
//! consumers in #783; they were not a hardware programming contract and
//! could not bind a physical controller. In particular, 1022:15e3 is
//! HDA, not ACP, and generic ACP RI upload registers from that scaffold
//! are not valid for Phoenix.

use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

/// Advanced Micro Devices, Inc.
pub const ACP_VENDOR: u16 = 0x1022;
/// Shared AMD ACP PCI ID; revision distinguishes the supported register map.
pub const ACP_RENOIR: u16 = 0x15E2;
/// Phoenix uses the same PCI device ID with revision 0x63.
pub const ACP_PHOENIX: u16 = ACP_RENOIR;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcpError {
    UnsupportedDevice,
    BarMapFailed,
    /// `ACP_VERSION` read 0xFFFFFFFF — device gone.
    DeviceGone,
    /// `ACP_SOFT_RESET_DONE` never asserted.
    ResetTimeout,
    /// `narf-firmware` had no entry for the requested RI blob.
    FirmwareMissing,
    /// RI blob was found but the device-side load sequence didn't
    /// land (`ACP_STATUS.READY` never asserted).
    FirmwareLoadFailed,
}

/// Decoded `ACP_VERSION` register.
#[derive(Copy, Clone, Debug)]
pub struct AcpVersion {
    pub raw: u32,
    /// Major version field (high byte of bits[31:16]).
    pub major: u8,
    /// Minor version field (low byte of bits[15:0]).
    pub minor: u8,
}

/// One AMD ACP6.0 host. Pre-firmware: BAR mapped, reset
/// completed. Post-firmware: RI loaded, RUN bit set, PDM
/// channels addressable.
pub struct AcpDevice {
    pub mmio: MmioRegion,
    pub version: AcpVersion,
    pub fw_loaded: bool,
}

impl core::fmt::Debug for AcpDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AcpDevice")
            .field("version", &self.version)
            .field("fw_loaded", &self.fw_loaded)
            .finish_non_exhaustive()
    }
}

impl AcpDevice {
    /// The retired generic ACP scaffold cannot identify a safe register map.
    /// Use the revision-specific `acp63::probe` for physical devices.
    /// # Safety
    /// Kept for source compatibility; no hardware is accessed.
    pub unsafe fn bring_up(
        _device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, AcpError> {
        Err(AcpError::UnsupportedDevice)
    }

    /// Firmware upload is not implemented by the retired scaffold.
    /// Native ACP 6.3 PDM capture does not need DSP firmware.
    /// # Safety
    /// Kept for source compatibility; no hardware is accessed.
    pub unsafe fn load_firmware(
        &mut self,
        _fw_authority: &Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    ) -> Result<(), AcpError> {
        Err(AcpError::UnsupportedDevice)
    }

    pub fn version(&self) -> AcpVersion {
        self.version
    }
    pub fn is_ready(&self) -> bool {
        self.fw_loaded
    }
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<AcpDevice>> = IrqSafeSpinLock::new(None);

/// Compatibility registration entry. Native ACP 6.3 lives in `acp63`.
/// The old I2S scaffold is not bound to physical devices.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    crate::acp63::probe(device, cap)
}

pub fn register_pci_driver() {
    crate::acp63::register_pci_driver();
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&AcpDevice) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Mutable callback variant — used by the PCM/DMA path that
/// programs ring-buffer state into the device.
pub fn with_controller_mut<R>(f: impl FnOnce(&mut AcpDevice) -> R) -> Option<R> {
    CONTROLLER.lock().as_mut().map(f)
}
