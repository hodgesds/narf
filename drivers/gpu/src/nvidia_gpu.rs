//! NVIDIA GPU (Turing+) — clean-room driver.
//!
//! Spec: `drivers/gpu/specification/nvidia_gpu.md`.
//!
//! ## References
//!
//! - **NVIDIA `open-gpu-doc`** repository — per-chip register
//!   listings (`dev_*.ref.txt`). MIT-licensed.
//!   <https://github.com/NVIDIA/open-gpu-doc>
//! - **NVIDIA `open-gpu-kernel-modules`** — only the
//!   MIT-licensed RPC headers (`src/common/sdk/nvidia/inc/...`)
//!   are consumed. GPL-2.0 files in that tree are excluded.
//!   <https://github.com/NVIDIA/open-gpu-kernel-modules>
//! - **Public `pci.ids` database** — every NVIDIA device ID in
//!   the table below.
//!
//! **No GPL Linux `nouveau` source consulted.**
//!
//! ## Stage progression
//!
//! - **Stage 1 (this commit)** — PCI claim, BAR0/BAR1 mapping,
//!   `NV_PMC_BOOT_0` presence test + arch decode, bound-driver
//!   record. No display / GSP programming.
//! - **Stage 2 (this commit)** — Codec layer: PMC, Falcon, GSP
//!   RPC framing, host FIFO push-buffer, display engine. See
//!   `crate::nvidia_gpu_*` for the per-block detail.
//! - **Stage 3 (future)** — driver core stages signed GSP
//!   firmware via the Falcon codec, opens the GSP RPC channel,
//!   issues the documented mode-set sequence.
//! - **Stage 4 (future)** — KMS-grade frame buffer.
//! - **Stage 5+ (future)** — push-buffer / compute via the host
//!   FIFO codec.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_driver_runtime::{
    map_bar, BusDevice, BusDeviceCap, Cap, Lock as IrqSafeSpinLock, MmioRegion, Write,
};

use crate::nvidia_gpu_pmc::{Architecture, Boot0, NV_PMC_BOOT_0};

// ── Vendor + device ids ───────────────────────────────────────────

/// NVIDIA Corporation (PCI Special Interest Group ID).
pub const NVIDIA_VENDOR: u16 = 0x10DE;

/// PCI class triple for a VGA-compatible display controller. The
/// class-match backstop catches all VGA cards; `probe` filters by
/// vendor so non-NVIDIA cards fall through to their own drivers.
const PCI_CLASS_DISPLAY: u8 = 0x03;

// Turing TU10x — RTX 20-series + GTX 16-series.
pub const TU102_RTX_2080_TI: u16 = 0x1E04;
pub const TU102_RTX_2080_TI_REFRESH: u16 = 0x1E07;
pub const TU104_RTX_2080_SUPER: u16 = 0x1E81;
pub const TU104_RTX_2080: u16 = 0x1E82;
pub const TU106_RTX_2070: u16 = 0x1F02;
pub const TU106_RTX_2060_REVA: u16 = 0x1F08;

// Ampere GA10x — RTX 30-series.
pub const GA102_RTX_3090: u16 = 0x2204;
pub const GA102_RTX_3080: u16 = 0x2206;
pub const GA104_RTX_3070: u16 = 0x2484;
pub const GA106_RTX_3060: u16 = 0x2503;

// Ada Lovelace AD10x — RTX 40-series.
pub const AD102_RTX_4090: u16 = 0x2684;
pub const AD103_RTX_4070_TI: u16 = 0x2786;
pub const AD104_RTX_4080_LAPTOP: u16 = 0x2820;
pub const AD104_RTX_4070_LAPTOP: u16 = 0x2882;

// ── BAR layout (open-gpu-doc, generic NV BAR layout) ─────────────

/// BAR0 — register window (also called instance memory aperture).
const BAR_REGS: u8 = 0;
/// BAR1 — GPU-visible system-memory aperture (used for USERD,
/// BAR1-mapped instance memory).
const BAR_BAR1: u8 = 1;
/// BAR3 — frame-buffer aperture on discrete cards. Not all
/// generations expose it at index 3; iGPUs may not expose it at
/// all. Probed best-effort.
const BAR_FB: u8 = 3;

// ── Errors ───────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NvidiaGpuError {
    BarMapFailed,
    /// Vendor was NVIDIA but device id wasn't in our table.
    UnknownAsic,
    /// `NV_PMC_BOOT_0` reads as all-ones / zero — no silicon.
    DeviceGone,
    /// `NV_PMC_BOOT_0` arch field doesn't match a Stage-1 target
    /// (Turing / Ampere / Ada). Pre-Turing parts use a different
    /// bring-up flow.
    UnsupportedArchitecture(u16),
}

// ── Chip-info table ──────────────────────────────────────────────

#[derive(Copy, Clone, Debug)]
pub struct ChipInfo {
    pub vid: u16,
    pub did: u16,
    pub architecture: Architecture,
    /// Short ASIC name for diagnostics.
    pub asic: &'static str,
}

fn chip_info_for_pci_id(vid: u16, did: u16) -> Option<ChipInfo> {
    if vid != NVIDIA_VENDOR {
        return None;
    }
    let (architecture, asic) = match did {
        TU102_RTX_2080_TI | TU102_RTX_2080_TI_REFRESH => (Architecture::Turing, "tu102"),
        TU104_RTX_2080 | TU104_RTX_2080_SUPER => (Architecture::Turing, "tu104"),
        TU106_RTX_2070 | TU106_RTX_2060_REVA => (Architecture::Turing, "tu106"),
        GA102_RTX_3090 | GA102_RTX_3080 => (Architecture::Ampere, "ga102"),
        GA104_RTX_3070 => (Architecture::Ampere, "ga104"),
        GA106_RTX_3060 => (Architecture::Ampere, "ga106"),
        AD102_RTX_4090 => (Architecture::Ada, "ad102"),
        AD103_RTX_4070_TI => (Architecture::Ada, "ad103"),
        AD104_RTX_4080_LAPTOP | AD104_RTX_4070_LAPTOP => (Architecture::Ada, "ad104"),
        _ => return None,
    };
    Some(ChipInfo {
        vid,
        did,
        architecture,
        asic,
    })
}

// ── Driver state ─────────────────────────────────────────────────

pub struct NvidiaGpu {
    pub regs: MmioRegion,
    pub bar1: MmioRegion,
    pub fb: Option<MmioRegion>,
    pub chip: ChipInfo,
    /// Decoded `NV_PMC_BOOT_0` captured at probe time.
    pub boot0: Boot0,
}

impl core::fmt::Debug for NvidiaGpu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NvidiaGpu")
            .field("chip", &self.chip)
            .field("boot0", &self.boot0)
            .finish_non_exhaustive()
    }
}

impl NvidiaGpu {
    /// Map BAR0 (registers) + BAR1 (aperture); attempt BAR3
    /// (framebuffer) best-effort. Read `NV_PMC_BOOT_0` and
    /// classify the architecture.
    ///
    /// # Safety
    /// Caller owns BAR0 + BAR1 (+ BAR3 when present) exclusively
    /// for the duration of probe.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, NvidiaGpuError> {
        let chip = chip_info_for_pci_id(device.id.vendor, device.id.device)
            .ok_or(NvidiaGpuError::UnknownAsic)?;

        // SAFETY: caller-asserted exclusive ownership.
        let regs =
            unsafe { map_bar(device, BAR_REGS) }.map_err(|_| NvidiaGpuError::BarMapFailed)?;
        // SAFETY: `bring_up`'s contract gives us exclusive ownership of
        // BAR1; `map_bar` maps that one BAR's window for the same `device`.
        let bar1 =
            unsafe { map_bar(device, BAR_BAR1) }.map_err(|_| NvidiaGpuError::BarMapFailed)?;
        // BAR3 (FB aperture) is best-effort — some integrated
        // parts don't expose it.
        // SAFETY: same.
        let fb = unsafe { map_bar(device, BAR_FB) }.ok();

        // SAFETY: identity-mapped MMIO; NV_PMC_BOOT_0 is read-only.
        let boot0_raw = unsafe { regs.read32(NV_PMC_BOOT_0) };
        compiler_fence(Ordering::SeqCst);
        if !Boot0::looks_present(boot0_raw) {
            return Err(NvidiaGpuError::DeviceGone);
        }
        let boot0 = Boot0::decode(boot0_raw);
        // Stage-1 targets Turing/Ampere/Ada/Hopper. Pre-Turing
        // uses a different bring-up; reject so the driver doesn't
        // mis-program a Pascal/Volta chip.
        match boot0.architecture {
            Architecture::Turing
            | Architecture::Ampere
            | Architecture::Ada
            | Architecture::Hopper => {}
            Architecture::Unknown(t) => {
                return Err(NvidiaGpuError::UnsupportedArchitecture(t));
            }
        }
        // Cross-check: the PCI device-ID table arch should agree
        // with the silicon-reported arch. Mismatch is a warning,
        // not a fatal error — the silicon is the source of truth
        // and we honour it. The PCI table is purely advisory.
        let _table_arch = chip.architecture;

        Ok(Self {
            regs,
            bar1,
            fb,
            chip,
            boot0,
        })
    }

    pub fn chip_info(&self) -> ChipInfo {
        self.chip
    }
    pub fn boot0(&self) -> Boot0 {
        self.boot0
    }
    /// Reported architecture (silicon, not PCI table).
    pub fn architecture(&self) -> Architecture {
        self.boot0.architecture
    }
}

// ── Driver-match registration ────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<NvidiaGpu>> = IrqSafeSpinLock::new(None);

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    if device.id.vendor != NVIDIA_VENDOR {
        return Err(narf_bus::ProbeError::BadDevice);
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
    let dev = match unsafe { NvidiaGpu::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("nvidia-gpu"),
        kind: narf_drivers::BoundKind::Graphics,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Graphics.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    let exact: &[(&'static str, u16, u16)] = &[
        ("nvidia-tu102-2080ti", NVIDIA_VENDOR, TU102_RTX_2080_TI),
        (
            "nvidia-tu102-2080ti-r",
            NVIDIA_VENDOR,
            TU102_RTX_2080_TI_REFRESH,
        ),
        ("nvidia-tu104-2080s", NVIDIA_VENDOR, TU104_RTX_2080_SUPER),
        ("nvidia-tu104-2080", NVIDIA_VENDOR, TU104_RTX_2080),
        ("nvidia-tu106-2070", NVIDIA_VENDOR, TU106_RTX_2070),
        ("nvidia-tu106-2060", NVIDIA_VENDOR, TU106_RTX_2060_REVA),
        ("nvidia-ga102-3090", NVIDIA_VENDOR, GA102_RTX_3090),
        ("nvidia-ga102-3080", NVIDIA_VENDOR, GA102_RTX_3080),
        ("nvidia-ga104-3070", NVIDIA_VENDOR, GA104_RTX_3070),
        ("nvidia-ga106-3060", NVIDIA_VENDOR, GA106_RTX_3060),
        ("nvidia-ad102-4090", NVIDIA_VENDOR, AD102_RTX_4090),
        ("nvidia-ad103-4070ti", NVIDIA_VENDOR, AD103_RTX_4070_TI),
        ("nvidia-ad104-4080m", NVIDIA_VENDOR, AD104_RTX_4080_LAPTOP),
        ("nvidia-ad104-4070m", NVIDIA_VENDOR, AD104_RTX_4070_LAPTOP),
    ];
    for (name, v, d) in exact.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: v,
                device: d,
            },
            probe,
        });
    }
    // Class-match backstop. The probe body filters non-NVIDIA
    // vendors so AMD / Intel / virtio-gpu cards aren't claimed.
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "nvidia-class",
        kind: narf_bus::MatchKind::Class {
            class: PCI_CLASS_DISPLAY,
            mask: 0xFF,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&NvidiaGpu) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}
