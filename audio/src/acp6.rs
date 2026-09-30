//! Compatibility surface for the retired generic ACP scaffold.
//!
//! Physical devices are registered through `acp63`, using Linux's
//! snd_pci_ps register map and revision/firmware checks. The historical I2S
//! model and its constants below remain for existing software tests; they are
//! not a hardware programming contract and cannot bind a physical controller.
//! In particular, 1022:15e3 is HDA, not ACP. Generic ACP_VERSION/RI upload
//! registers from this scaffold are not valid for Phoenix.

use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

/// Advanced Micro Devices, Inc.
pub const ACP_VENDOR: u16 = 0x1022;
/// Shared AMD ACP PCI ID; revision distinguishes the supported register map.
pub const ACP_RENOIR: u16 = 0x15E2;
/// Phoenix uses the same PCI device ID with revision 0x63.
pub const ACP_PHOENIX: u16 = ACP_RENOIR;

// Historical model constants, used only by unbound legacy helpers.
pub(crate) mod regs {
    pub const ACP_VERSION: u64 = 0x100;
    pub const CONTROL_CLKEN: u32 = 1 << 0;
    pub const CONTROL_RUN: u32 = 1 << 1;

    // ── I2S TX path (passthrough DMA) ──────────────────────────────
    //
    // ACP6 register-file offsets for the I2S0 TX engine. The base
    // shifted between ACP3 and ACP6; values below match
    // Linux `sound/soc/amd/renoir/acp3x.c` (`ACP_BTTDM_*` /
    // `ACP_I2S_TX_*`) confirmed against the Renoir / Cezanne PPR
    // §13.7 "I2S Controller".
    //
    // The engine reads samples from a contiguous ring buffer in
    // system RAM (the controller is bus-master) and pushes them
    // into the I2S TX FIFO; the FIFO drains onto the BCLK/LRCLK
    // wire pair driving the off-die codec (WM8960 in our case).
    //
    // We use I2S0 ("BT-TDM" in AMD parlance — the first of three
    // I2S blocks on Renoir). Channels: BT-TDM (0x1242), HS-TDM
    // (0x14A0), I2S-SP (0x1342). All three are shape-identical.

    /// Ring buffer base address (low / high). Phys.
    pub const ACP_I2STX_RINGBUFADDR: u64 = 0x1242;
    pub const ACP_I2STX_RINGBUFSIZE: u64 = 0x1242 + 0x04;
    /// FIFO base address — where the engine pushes samples that
    /// drain to the wire. ACP scratch RAM, programmed below.
    pub const ACP_I2STX_FIFOADDR: u64 = 0x1242 + 0x08;
    pub const ACP_I2STX_FIFOSIZE: u64 = 0x1242 + 0x0C;
    pub const ACP_I2STX_DMA_SIZE: u64 = 0x1242 + 0x10;
    pub const ACP_I2STX_LINEARPOSITION_CNTR_LOW: u64 = 0x1242 + 0x14;
    pub const ACP_I2STX_LINEARPOSITION_CNTR_HIGH: u64 = 0x1242 + 0x18;
    pub const ACP_I2STX_INTR_WATERMARK_SIZE: u64 = 0x1242 + 0x1C;

    /// I2S transmit interrupt enable & frame-format register.
    /// Bit 0 = TX_EN, bit 1..3 = word length code.
    pub const ACP_BTTDM_IER: u64 = 0x3000;
    /// I2S receive interrupt enable — used by future capture path.
    #[allow(dead_code)]
    pub const ACP_BTTDM_IRER: u64 = 0x3004;
    /// I2S transmit frame config (slot count, slot bits, word len).
    /// See Linux `sound/soc/amd/renoir/acp3x.c::acp3x_dai_i2s_hwparams`.
    pub const ACP_BTTDM_TXFRMT: u64 = 0x3008;
    /// I2S audio link control. Bit 0 = link enable; bits 4..6 =
    /// FIFO depth select. Matches Linux `ACP_BTTDM_ITER` semantics.
    pub const ACP_BTTDM_ITER: u64 = 0x300C;

    /// I2S external clock generator — BCLK / LRCLK divider against
    /// the 25 MHz ACP reference clock. Linux `acp3x.c` programs this
    /// inside `acp3x_dai_set_clkdiv()`.
    pub const ACP_I2S_AUDIO_CLK_DIV: u64 = 0x504C;

    /// ACP_EXTERNAL_INTR_STAT — bit 17 = I2S TX DMA-complete. Read
    /// by the eventual IRQ-driven completion path; the current
    /// driver polls `ACP_I2STX_LINEARPOSITION_CNTR_*` instead.
    #[allow(dead_code)]
    pub const ACP_EXTERNAL_INTR_STAT: u64 = 0x1A0C;
    pub const ACP_EXTERNAL_INTR_ENB: u64 = 0x1A04;
    pub const EXTINTR_I2STX_DMA_DONE: u32 = 1 << 17;

    /// `ACP_BTTDM_IER` bits.
    pub const TDM_TX_ENABLE: u32 = 1 << 0;
    /// `ACP_BTTDM_ITER` bits — bit 0 starts the link engine.
    pub const TDM_ITER_ENABLE: u32 = 1 << 0;

    /// Ring buffer size for the passthrough TX engine. One page
    /// (4 KiB) — matches HDA's period choice, and lines up with
    /// Linux's ACP3X minimum-period (`ACP3x_MIN_PERIOD = 64`,
    /// scaled by frame size: 16-bit stereo @ 48 kHz × 21 ms ≈ 4 KiB).
    pub const I2STX_RING_BYTES: u32 = 4096;
    /// FIFO depth — ACP scratch-RAM bytes reserved for the I2S0 TX
    /// FIFO. Linux uses 512 (`ACP_I2S_FIFO_SIZE`).
    pub const I2STX_FIFO_BYTES: u32 = 512;
    /// Scratch-RAM offset to place the FIFO. ACP scratch RAM is at
    /// BAR0+0x100_0000 (Renoir PPR §13.6); 0x0 = first slot.
    pub const I2STX_FIFO_SCRATCH_OFFSET: u32 = 0x0000_0000;
}

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
    /// I2S TX engine has been programmed + ring buffer allocated.
    /// Set by `acp6_pcm::prepare_i2s0_tx`; cleared on stop.
    pub(crate) i2s_tx_prepared: bool,
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
