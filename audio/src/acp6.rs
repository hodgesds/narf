//! AMD ACP6.0 (Audio Coprocessor) PDM digital-mic driver — clean-room.
//!
//! ## Reference
//!
//! - AMD Family 19h Models 70h-7Fh (Phoenix) SoC PPR: §13 Audio
//!   Coprocessor (ACP). Public document (`PPR_Family_19h_Model_70h.pdf`).
//!   Section numbers below (`§13.x`) refer to that document.
//! - The PCI configuration shape matches every AMD ACP block since
//!   ACP3.0 (Picasso); the PCI ID change tracks SoC family.
//!
//! No GPL Linux `sof-amd-acp` source consulted; the bring-up sequence
//! is the public PPR's documented reset + RI-load handshake.
//!
//! ## Targets
//!
//! - `1022:15E2` — AMD Phoenix ACP6.0 ("Audio Coprocessor"). The
//!   user's Ryzen 7 PRO 8840HS laptop exposes one of these for the
//!   integrated array-mic input. `lspci -nn` lists it as
//!   `Multimedia controller [0480]`.
//!
//! ## Stage-6 cut
//!
//! The ACP6.0 DSP requires a vendor-signed runtime image (`sof-rn.ri`
//! / `acp_rn.ri`) to be loaded into the on-die scratch RAM via the
//! ACP-DMA before PDM capture can produce real samples. NARF's
//! `narf-firmware` registry handles the lookup + signature
//! verification side; the device-side load sequence (BAR0 register
//! programming + DMA wait + RUN bit) lives here. Without the
//! firmware blob staged in the registry, this driver:
//!
//! - Maps BAR0
//! - Asserts + deasserts ACP soft reset (§13.3.1)
//! - Records `BoundDriver { kind: Audio, … }` at the audio domain
//!
//! Once the RI blob is registered (typically by initramfs unpack
//! at Stage::Late), `load_firmware()` programs the ACP RI-load
//! sequence and confirms `ACP_STATUS.READY` asserts. PCM capture
//! and the mixer surface (`narf-audio` integration) come after.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

/// Advanced Micro Devices, Inc.
pub const ACP_VENDOR: u16 = 0x1022;
/// AMD Phoenix ACP6.0 Audio Coprocessor.
pub const ACP_PHOENIX: u16 = 0x15E2;

// ── BAR0 register-block offsets ────────────────────────────────────
//
// The ACP register file at BAR0 + 0x0 is the same shape across
// ACP3.0 → ACP6.x; SoC-specific bits are gated through the
// `ACP_VERSION` register at +0x100. References below are the
// Phoenix PPR §13.3 register table.
mod regs {
    /// `ACP_VERSION` — vendor / revision triple. Used as a
    /// presence test (`0xFFFFFFFF` ↔ device-gone / D3cold).
    pub const ACP_VERSION: u64 = 0x100;
    pub const VERSION_GONE: u32 = 0xFFFF_FFFF;

    /// `ACP_SOFT_RESET` — write the SOFT_RESET bit, poll
    /// `ACP_SOFT_RESET_DONE`.
    pub const ACP_SOFT_RESET: u64 = 0x104;
    /// `ACP_CONTROL` — bit 0 = ClkEn, bit 1 = Run.
    pub const ACP_CONTROL: u64 = 0x108;
    /// `ACP_STATUS` — bit 0 = ACP_BUSY, bit 1 = READY.
    pub const ACP_STATUS: u64 = 0x10C;

    /// `ACP_RI_ADDR` — phys base (low / high split).
    pub const ACP_RI_ADDR_LO: u64 = 0x130;
    pub const ACP_RI_ADDR_HI: u64 = 0x134;
    /// `ACP_RI_SIZE` — bytes.
    pub const ACP_RI_SIZE: u64 = 0x138;
    /// `ACP_RI_KICK` — write 1 to start the DMA load.
    pub const ACP_RI_KICK: u64 = 0x13C;

    /// `ACP_SOFT_RESET` bits.
    pub const RESET_REQUEST: u32 = 1 << 0;
    pub const RESET_DONE: u32 = 1 << 16;
    /// `ACP_CONTROL` bits.
    pub const CONTROL_CLKEN: u32 = 1 << 0;
    pub const CONTROL_RUN: u32 = 1 << 1;
    /// `ACP_STATUS` bits.
    pub const STATUS_READY: u32 = 1 << 1;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcpError {
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
    /// Map BAR0, assert + deassert ACP soft reset, leave RUN clear.
    /// Real PCM capture follows a successful `load_firmware`.
    ///
    /// # Safety
    /// Caller owns BAR0 exclusively for the duration of probe.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, AcpError> {
        // SAFETY: caller-authority over BAR0.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| AcpError::BarMapFailed)?;

        // Probe ACP_VERSION as a presence test.
        // SAFETY: identity-mapped MMIO.
        let raw = unsafe { mmio.read32(regs::ACP_VERSION) };
        if raw == regs::VERSION_GONE {
            return Err(AcpError::DeviceGone);
        }
        let major = ((raw >> 24) & 0xFF) as u8;
        let minor = ((raw >> 16) & 0xFF) as u8;
        let version = AcpVersion { raw, major, minor };

        // Assert ACP soft reset, wait for RESET_DONE. The PPR
        // notes: the bit at +16 latches `1` once reset settles;
        // the request bit self-clears.
        // SAFETY: same.
        unsafe {
            mmio.write32(regs::ACP_SOFT_RESET, regs::RESET_REQUEST);
        }
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay
        // alive during ACP soft-reset settle. 100 ms wedge
        // threshold (typical reset latches in <1 ms per AMD PPR
        // §13.3.2).
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { mmio.read32(regs::ACP_SOFT_RESET) } & regs::RESET_DONE != 0,
            narf_time::Deadline::after_ms(100),
        );
        if !done {
            return Err(AcpError::ResetTimeout);
        }

        // Enable the ACP clock so RI DMA load can run; leave RUN
        // clear (set on firmware-load completion).
        // SAFETY: same.
        unsafe {
            mmio.write32(regs::ACP_CONTROL, regs::CONTROL_CLKEN);
        }

        Ok(Self {
            mmio,
            version,
            fw_loaded: false,
        })
    }

    /// Stage the ACP RI runtime image via the kernel firmware
    /// registry, drive the DMA load handshake, set RUN.
    ///
    /// Sequence per PPR §13.3.4:
    ///   1. Program `ACP_RI_ADDR_LO/HI` from the blob's phys.
    ///   2. Program `ACP_RI_SIZE` from the blob's byte length.
    ///   3. Write 1 to `ACP_RI_KICK`.
    ///   4. Poll `ACP_STATUS` until `READY` asserts (~10 ms).
    ///   5. Set `ACP_CONTROL.RUN`.
    ///
    /// Returns `FirmwareMissing` if the registry has no entry.
    /// Returns `FirmwareLoadFailed` on any device-side timeout.
    ///
    /// # Safety
    /// Caller owns BAR0 exclusively. The blob's `view().phys` must
    /// remain valid for the duration of the load — the cap stays
    /// alive until this function returns.
    pub unsafe fn load_firmware(
        &mut self,
        fw_authority: &Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    ) -> Result<(), AcpError> {
        let cap = narf_firmware::open("amd/acp/sof-rn.ri", fw_authority).map_err(|e| match e {
            narf_firmware::FirmwareError::NotFound => AcpError::FirmwareMissing,
            _ => AcpError::FirmwareLoadFailed,
        })?;
        let view = narf_firmware::view_of(&cap).map_err(|_| AcpError::FirmwareLoadFailed)?;
        let phys = view.phys;
        let len = view.bytes.len() as u32;
        // SAFETY: BAR0 mapped, exclusive owner.
        unsafe {
            self.mmio.write32(regs::ACP_RI_ADDR_LO, phys as u32);
            self.mmio.write32(regs::ACP_RI_ADDR_HI, (phys >> 32) as u32);
            self.mmio.write32(regs::ACP_RI_SIZE, len);
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            self.mmio.write32(regs::ACP_RI_KICK, 1);
        }

        // Wait for ACP_STATUS.READY. responsive_spin_until ticks
        // sleep_pumps so cursor/FB/serial stay alive across the
        // ~10 ms RI DMA load. 500 ms wedge threshold (50x typical
        // per AMD PPR §13.3.4).
        let ready = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { self.mmio.read32(regs::ACP_STATUS) } & regs::STATUS_READY != 0,
            narf_time::Deadline::after_ms(500),
        );
        if !ready {
            return Err(AcpError::FirmwareLoadFailed);
        }

        // Set RUN.
        // SAFETY: same.
        unsafe {
            self.mmio
                .write32(regs::ACP_CONTROL, regs::CONTROL_CLKEN | regs::CONTROL_RUN);
        }

        // Record the firmware-version coupling for observability.
        narf_drivers::set_bound_firmware(
            "acp6",
            narf_drivers::BoundFirmware {
                blob_name: alloc::string::String::from("amd/acp/sof-rn.ri"),
                sha256: view.sha256,
                signer: view.signer,
                version: None,
            },
        );

        self.fw_loaded = true;
        Ok(())
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

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority.
    let dev = match unsafe { AcpDevice::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("acp6"),
        kind: narf_drivers::BoundKind::Audio,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Audio.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "acp6",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: ACP_VENDOR,
            device: ACP_PHOENIX,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&AcpDevice) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}
