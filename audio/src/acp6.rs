//! AMD ACP (Audio Coprocessor) driver — clean-room.
//!
//! Covers ACP3.x → ACP6.x. The PCI register file at BAR0 is the same
//! shape across the family; the SoC version is read from the
//! `ACP_VERSION` register at offset `0x100`. Targeted SoCs:
//!
//! | PCI ID    | SoC family            | ACP rev | Status        |
//! |-----------|-----------------------|---------|---------------|
//! | 1022:15E2 | Renoir / Lucienne / Cezanne (Zen2 APU) | 6.0 | bring-up target |
//! | 1022:15E3 | Pink Sardine          | 6.x     | match-only    |
//! | 1022:15BE | Rembrandt (Zen3+)     | 6.2     | match-only    |
//! | 1022:638F | Mero / Mendocino / newer parts | 6.3 | match-only    |
//!
//! The user's bring-up box is AMD Family 0x17 Models 0x30..0xAF —
//! Renoir / Lucienne / Cezanne — which exposes `1022:15E2` as
//! `Multimedia controller [0480]`. See user memory
//! `project_bringup_target.md`.
//!
//! ## References
//!
//! All citations below are GPL-2.0-or-later Linux sources — NARF
//! is itself GPL-2.0-or-later as of 2026-05-20, so direct citation
//! and adaptation is allowed.
//!
//! - **AMD Renoir / Cezanne PPR**, §13 "ACP" — register table for
//!   `ACP_VERSION` / `ACP_SOFT_RESET` / `ACP_CONTROL` / `ACP_STATUS`
//!   and the I2S DMA block.
//! - Linux `sound/soc/amd/raven/acp3x-pcm-dma.c` (lines ~80-260):
//!   ACP DMA descriptor-ring shape used by the I2S TX engine —
//!   `ACP_I2S_TX_RINGBUFADDR / RINGBUFSIZE / LINKPOSITIONCNTR`,
//!   plus the FIFO-watermark register pair. The ACP6 register
//!   offsets shifted from ACP3 — see `sound/soc/amd/acp/acp-mach.c`
//!   for the version multiplexing.
//! - Linux `sound/soc/amd/renoir/acp3x.c` — ACP6 PCI probe + soft
//!   reset; reset sequence below mirrors `acp3x_init()`.
//! - Linux `sound/soc/amd/acp/acp-pci.c` — PCI ID table; the
//!   shared device id `0x15E2` is reused across Renoir / Lucienne
//!   / Cezanne (the SoC family is distinguishable only via CPUID).
//! - Linux `sound/soc/codecs/wm8960.c` — WM8960 codec init verbs;
//!   matched in `audio/src/wm8960.rs`.
//! - Wolfson **WM8960 datasheet**, Rev 4.4 (public, non-GPL).
//!
//! ## Operating mode
//!
//! Passthrough I2S DMA: the ACP block is brought out of reset, its
//! clock is enabled, and the I2S0 TX engine is programmed to stream
//! PCM frames from a kernel-side ring buffer to the off-die codec.
//! No DSP firmware blob is required for this mode — the on-die
//! ACP DSP can stay parked. Linux operates the simpler ACP3X parts
//! the same way (`sound/soc/amd/raven/acp3x-i2s.c`).
//!
//! The optional `load_firmware()` path stages a vendor-signed
//! runtime image (`sof-rn.ri`) into the on-die scratch RAM for
//! parts that *do* need DSP-side processing — kept here as a
//! capture-path future, not used by play_pcm.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

/// Advanced Micro Devices, Inc.
pub const ACP_VENDOR: u16 = 0x1022;
/// AMD Renoir / Lucienne / Cezanne ACP6.0 (Zen2 APU bring-up target).
/// Linux `sound/soc/amd/acp/acp-pci.c` uses this same device id
/// across all three SKUs.
pub const ACP_RENOIR: u16 = 0x15E2;
/// Legacy alias for source-compat — same silicon as `ACP_RENOIR`.
pub const ACP_PHOENIX: u16 = ACP_RENOIR;
/// AMD Pink Sardine ACP.
pub const ACP_PINK_SARDINE: u16 = 0x15E3;
/// AMD Rembrandt ACP6.2.
pub const ACP_REMBRANDT: u16 = 0x15BE;
/// Newer ACP (Mero / Mendocino / 2024+ parts).
pub const ACP_MERO: u16 = 0x638F;

// ── BAR0 register-block offsets ────────────────────────────────────
//
// The ACP register file at BAR0 + 0x0 is the same shape across
// ACP3.0 → ACP6.x; SoC-specific bits are gated through the
// `ACP_VERSION` register at +0x100. References below are the
// Phoenix PPR §13.3 register table.
pub(crate) mod regs {
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
    pub const ACP_I2STX_RINGBUFADDR: u64 = 0x1242 + 0x00;
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
            i2s_tx_prepared: false,
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

/// Register all known AMD ACP PCI ids with the bus match table.
///
/// Multiple registrations rather than a class-match because AMD ACP
/// uses PCI class `0x04 / 0x80` ("multimedia controller / other"),
/// which would also pick up unrelated DSPs. Linux's
/// `sound/soc/amd/acp/acp-pci.c` does the same explicit ID table.
pub fn register_pci_driver() {
    for (name, device) in [
        ("acp6-renoir", ACP_RENOIR),
        ("acp6-pink-sardine", ACP_PINK_SARDINE),
        ("acp6-rembrandt", ACP_REMBRANDT),
        ("acp6-mero", ACP_MERO),
    ] {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: ACP_VENDOR,
                device,
            },
            probe,
        });
    }
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
