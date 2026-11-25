//! Intel integrated graphics (Gen12 Xe-LP / Xe-LPG) — clean-room driver.
//!
//! Spec: `drivers/gpu/specification/intel_gpu.md`.
//!
//! ## References
//!
//! - **Intel "Linux Graphics Programmer's Reference Manual" hub** —
//!   per-generation public PDFs.
//!   <https://www.intel.com/content/www/us/en/docs/graphics-for-linux/developer-reference/1-0/overview.html>
//! - **Tiger Lake PRM** (the conservative reference target):
//!   - **Vol. 12** — Display DDIs / Plane Programming.
//!   - **Vol. 14** — Display Engine (pipes + transcoders).
//!   - **Vol. 11** — Display Engine Registers (clocks).
//!   - **Vol.  5** — Memory Views (GTT / PPGTT).
//! - **Alder Lake PRM** — same Gen12 register surface; useful
//!   cross-check for ADL-S/-P iGPUs.
//! - **Meteor Lake display PRM** — Xe-LPG display engine.
//! - **Linux `include/drm/intel/pciids.h`** — the current exact Intel
//!   graphics PCI-ID families and primary authority for the device table.
//!   Six older ADL-P rows retained from public `pci.ids` share its qualified
//!   profile. IDs are admitted only when the corresponding register/firmware
//!   family is modeled; source-known but unqualified families fail closed.
//!
//! **No GPL Linux `i915` / `xe` source consulted for the driver
//! logic.** Register *values* in sibling modules are cross-checked
//! against public PRM volumes; where a PRM volume was not directly
//! readable, the module doc says so.
//!
//! ## Stage progression
//!
//! - **Stage 1** — PCI claim, BAR0 (GTTMMADR) mapping,
//!   generation-aware presence test (`GMD_ID` on Gen12+,
//!   PCI config-space re-read on pre-GMD Gen11/Gen9), bound-driver
//!   record.
//! - **Stage 2** — Codec layer: GMBUS, DPLL, pipes, DDI, GTT
//!   register-codecs in sibling `crate::intel_gpu_*` modules.
//! - **Stage 3** — Modeset orchestrator takes over the firmware
//!   display (see `intel_gpu_modeset`).
//! - **Lane 1 (#1010)** — identification is a single canonical
//!   device table (registration and classification both derive
//!   from it, pinned by a census fixture); probe is panic-free
//!   and owns its scanout allocation; display programming on the
//!   shared probe path is gated to Gen12 + Meteor Lake — Lunar
//!   Lake / Panther Lake identify and announce, and drive
//!   display only through their opted-in per-device routes
//!   (display 20 / display 30). Gen11 (Ice Lake / Elkhart Lake /
//!   Jasper Lake) identifies and announces the same way — its
//!   BAR0 partitioning and GuC firmware family are modelled, its
//!   presence test is the pre-GMD config-space re-read — and
//!   since Lane 5 its internal-panel modeset is admitted on the
//!   shared probe path (display clocks, DPLL, watermarks, DDI
//!   tables, first light on the internal display,
//!   fixture-validated, silicon untested). External display and
//!   backlight are admitted since Lane 8 (Gen11 §12.3; Gen9
//!   Lane 8, §12.7), and
//!   GT execution stays gated until the Gen11 lanes land
//!   (PTE format, execlists, GuC load).

#[path = "intel_gpu_external_stop.rs"]
pub(crate) mod external_stop;

use core::sync::atomic::{compiler_fence, Ordering};

use narf_driver_runtime::{
    map_bar, BusDevice, BusDeviceCap, Cap, Lock as IrqSafeSpinLock, MmioRegion, Write,
};

use crate::intel_gpu_regions::{self, Region, RegionGeneration, RegionKind};

// ── Vendor + device ids ───────────────────────────────────────────

#[path = "intel_gpu_pci_ids.rs"]
mod ids;
pub use ids::*;

/// PCI class triple for a VGA-compatible display controller. The
/// class-match backstop catches all VGA cards; `probe` filters by
/// vendor so non-Intel cards fall through to their own drivers.
const PCI_CLASS_DISPLAY: u8 = 0x03;

impl Generation {
    /// Map the sub-architecture to the BAR0 region-enumeration
    /// generation. TGL / ADL / RPL share the Xe-LP MMIO map
    /// (`RegionGeneration::Gen12`); Gen9 (SKL / KBL / CFL / WHL /
    /// CML) shares that partitioning (`__gen11_fw_ranges`) and maps
    /// to its own `RegionGeneration::Gen9` table, whose contents
    /// are the verified Gen12 table carried over; Gen11 (ICL / EHL / JSL)
    /// shares that partitioning (`__gen11_fw_ranges`) and maps
    /// to its own `RegionGeneration::Gen11` table, whose contents
    /// are the verified Gen12 table carried over; Meteor Lake maps
    /// to the Xe-LPG region table (#1016); Lunar Lake maps to the
    /// Xe2-LPD table (display 20) and Panther Lake to the
    /// Xe3-LPD table (display 30) — separate tables sharing the
    /// Xe-LPG BAR0 layout (one Linux forcewake table,
    /// `__mtl_fw_ranges`, covers all three), so the display IPs
    /// are never conflated.
    pub const fn region_generation(self) -> Option<RegionGeneration> {
        match self {
            // Gen9 LP shares the Gen9 register surface and forcewake table
            // (`intel_uncore.c`: every graphics 9 part takes `__gen9_fw_ranges`).
            Generation::Skylake | Generation::Broxton => Some(RegionGeneration::Gen9),
            Generation::IceLake => Some(RegionGeneration::Gen11),
            Generation::TigerLake | Generation::RocketLake | Generation::AlderLake => {
                Some(RegionGeneration::Gen12)
            }
            Generation::MeteorLake => Some(RegionGeneration::XeLpg),
            Generation::LunarLake => Some(RegionGeneration::Xe2Lpd),
            Generation::PantherLake => Some(RegionGeneration::Xe3Lpd),
        }
    }

    /// Whether the generation publishes the Xe-era `GMD_ID` /
    /// `MTCFG_TRBLK` identification registers. Gen12+ does;
    /// Gen11 and Gen9 predate GMD_ID, so what 0xD8C/0xFF8 read on
    /// Gen11/Gen9 silicon is ungrounded and must never be used as a
    /// presence signal (a 0 read would pass the all-ones check
    /// spuriously). Stage-1 presence for Gen11/Gen9 re-reads PCI
    /// config space instead.
    pub const fn has_gmd_id(self) -> bool {
        !matches!(
            self,
            Generation::IceLake | Generation::Skylake | Generation::Broxton
        )
    }

    /// Whether this lane programs the display engine for the
    /// generation through the Gen12/Meteor Lake probe path.
    /// Gen12 (TGL/ADL/RPL) and Meteor Lake (Xe-LPG, #1016) have
    /// validated register sequences on that path. Gen11 (Ice
    /// Lake, Lanes 5 + 8) joins them for the internal panel and
    /// the external outputs: its modeset (ICL CDCLK / DPLL /
    /// watermarks / DDI tables / MG PLL / HDMI) is
    /// fixture-validated and silicon untested. Lunar Lake
    /// (Xe2-LPD, display 20) and Panther Lake (Xe3-LPD, display
    /// 30) stay `false` here deliberately even though their
    /// display is driven: each has its own opted-in per-device
    /// route (`intel_gpu_xe2lpd::probe_route` /
    /// `intel_gpu_xe3lpd::probe_route`, `narf.intel.lnl_display`
    /// / `narf.intel.ptl_display`) with its own owned modeset,
    /// and this predicate gates the Gen12/MTL probe branch,
    /// which precedes those routes in `probe` — flipping it
    /// would run the Gen12 takeover (which returns
    /// `UnsupportedGeneration` for both) instead of the owned
    /// route, and would arm PSR below, which both display IPs
    /// refuse. A flip needs a probe restructure plus hardware
    /// validation, not a one-line gate change.
    pub const fn display_supported(self) -> bool {
        matches!(
            self,
            Generation::TigerLake
                | Generation::AlderLake
                | Generation::MeteorLake
                | Generation::IceLake
                | Generation::Skylake
                | Generation::Broxton
        )
    }

    /// The modeset-level external outputs are implemented for
    /// Gen12, for Gen11 Ice Lake (Lane 8: combo-PHY A/B DP +
    /// HDMI, TC1–TC4 MG PLL + DP + HDMI, fixture-validated,
    /// silicon untested), and for Gen9 Skylake (Gen9 Lane 8:
    /// DDI B–E DP + HDMI, SKL WRPLL + DDI tables, same
    /// fixture-validated, silicon-untested status). The HPD /
    /// external-session layer (`enable_external_hpd`,
    /// `dp_connect`, `hdmi_connect`, `mst_connect`) admits each
    /// of them by its source family. Rocket Lake joins for its
    /// combo DDI B and its TC1/TC2 combo ports (DDI D/E, PHY C/D,
    /// arbitrated over its three PLLs), with its own CDCLK table,
    /// power-well map, DPCLKA layout and hotplug pins. Its
    /// internal panel and backlight stay gated
    /// (`display_supported`, `backlight_supported`).
    pub const fn external_display_supported(self) -> bool {
        matches!(
            self,
            Generation::TigerLake
                | Generation::RocketLake
                | Generation::AlderLake
                | Generation::IceLake
                | Generation::Skylake
                | Generation::Broxton
        )
    }

    /// Whether the backlight PWM install is valid for the
    /// generation. Two layouts: Skylake drives the SPT PWM
    /// block (`BLC_PWM_PCH_CTL1`/`CTL2` 0xC8250/54, duty RMW
    /// into CTL2's low 16 bits, max = CTL2 >> 16, 24 MHz,
    /// `SPT_PWM_GRANULARITY` bit 0 of `SOUTH_CHICKEN1`
    /// 0xC2000 — Linux `spt_pwm_funcs`,
    /// `display/intel_backlight.c`), and Ice Lake shares the
    /// BXT-style block (`BXT_BLC_PWM_CTL1`/`FREQ1`/`DUTY1`
    /// 0xC8250/54/58 + `SOUTH_CHICKEN1` 0xC2000 bit 25 —
    /// Linux drives ICL through the same `cnp_pwm_funcs`
    /// (`bxt_set_backlight` / `bxt_get_backlight`) — "CNP has
    /// the BXT implementation of backlight, but with only one
    /// controller". MTL's backlight path is owned by the
    /// backlight composition lane (PR #1037, #947/#949/#951),
    /// which flips this predicate when the MTL registers land.
    /// Keeping it separate from `display_supported` lets the
    /// MTL modeset ship without claiming a backlight it cannot
    /// drive. The install's controller-1 hardcoding is
    /// pre-existing Gen12 behavior (Linux takes the VBT
    /// controller, defaulting to 0); on a VBT-controller-0
    /// part FREQ1 may read 0 and the install no-ops harmlessly.
    pub const fn backlight_supported(self) -> bool {
        matches!(
            self,
            Generation::TigerLake
                | Generation::AlderLake
                | Generation::IceLake
                | Generation::Skylake
                | Generation::Broxton
        )
    }
}

/// What Stage-1 knows about a probed Intel iGPU.
#[derive(Copy, Clone, Debug)]
pub struct ChipInfo {
    pub vid: u16,
    pub did: u16,
    pub generation: Generation,
    /// Short ASIC name for diagnostics.
    pub asic: &'static str,
}

fn unqualified_probe_message(did: u16) -> Option<&'static str> {
    if CRI_IDS.contains(&did) {
        Some("recognized Crescent Island — GuC firmware profile absent; execution gated")
    } else if NVLP_IDS.contains(&did) {
        Some("recognized Nova Lake-P — GuC firmware profile absent; execution gated")
    } else {
        None
    }
}

fn chip_info_for_pci_id(vid: u16, did: u16) -> Option<ChipInfo> {
    if vid != INTEL_VENDOR {
        return None;
    }
    DEVICE_TABLE
        .iter()
        .find(|e| e.did == did)
        .map(|e| ChipInfo {
            vid,
            did,
            generation: e.generation,
            asic: e.asic,
        })
}

/// Scanout stride for a 32-bpp linear surface of `width` pixels,
/// padded up to the display engine's 64-byte stride alignment
/// (TGL PRM Vol. 14, `PLANE_STRIDE`). Before lane 1 the probe
/// used the unpadded `width * 4`, which `build_primary_plane`
/// rejects for widths like 1366 — and the probe `.expect()`ed
/// the result, panicking during Stage::Device probe on a common
/// laptop panel size.
pub const fn padded_stride_bytes(width: u32) -> u32 {
    let raw = width * 4;
    (raw + 63) & !63
}

/// Total scanout allocation size for `width`x`height` at the
/// padded stride.
pub const fn scanout_size_bytes(width: u32, height: u32) -> u64 {
    padded_stride_bytes(width) as u64 * height as u64
}

// ── BAR layout (TGL PRM Vol. 12 §"Memory Map and Configuration") ─

/// `GTTMMADR` — Graphics Translation Table + Memory-Mapped
/// register window. BAR0 on every Gen12 iGPU; the low half is
/// MMIO registers, the high half is the GTT entry array.
const BAR_GTTMMADR: u8 = 0;
/// `GMADR` — Graphics Memory aperture (stolen-memory frame
/// buffer). BAR2 on iGPUs.
const BAR_GMADR: u8 = 2;

// ── Identification register ──────────────────────────────────────

/// `GMD_ID` — Graphics Media Device Identifier (TGL PRM Vol. 12
/// §"Device Identification"). MMIO offset `0x000D8C`.
const GMD_ID: u64 = 0x0000_0D8C;

/// `MTCFG_TRBLK` cookie (TGL PRM Vol. 12 §"Identifier").
const MTCFG_TRBLK: u64 = 0x0000_0FF8;

// ── Errors ───────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IntelGpuError {
    BarMapFailed,
    /// Vendor is Intel but the device id isn't in the table.
    UnknownAsic,
    /// MMIO presence test read garbage (all-ones).
    DeviceGone,
}

/// Pure Stage-1 presence decision, factored out of `bring_up` so
/// the generation-aware rule is fixture-testable without MMIO
/// hardware. `gmd` carries the (`GMD_ID`, `MTCFG_TRBLK`) pair and
/// is `Some` only on generations that publish those registers;
/// `config_id` carries the PCI config-space vendor/device dword
/// and is only consulted on pre-GMD generations.
///
/// - Gen12+: the device is present iff neither identity read is
///   all-ones (a mapped BAR over a gone device reads all-ones).
///   Returns the `GMD_ID` value.
/// - Gen11/Gen9: the device is present iff the config-space re-read
///   is not all-ones. The MMIO pair is ignored entirely — even
///   all-ones `GMD_ID`/`MTCFG_TRBLK` values cannot refuse a
///   Gen11/Gen9 part, because those offsets predate GMD_ID and their
///   Gen11/Gen9 values are ungrounded. Returns `None`.
fn stage1_presence(
    generation: Generation,
    gmd: Option<(u32, u32)>,
    config_id: u32,
) -> Result<Option<u32>, IntelGpuError> {
    if generation.has_gmd_id() {
        let (gmd_id, trblk) = gmd.ok_or(IntelGpuError::DeviceGone)?;
        if gmd_id == 0xFFFF_FFFF || trblk == 0xFFFF_FFFF {
            return Err(IntelGpuError::DeviceGone);
        }
        Ok(Some(gmd_id))
    } else {
        if config_id == 0xFFFF_FFFF {
            return Err(IntelGpuError::DeviceGone);
        }
        Ok(None)
    }
}

// ── Driver state ─────────────────────────────────────────────────

/// The scanout allocation owned by the probed device. Before
/// lane 1 the probe dropped the `Vec<PhysFrame>` returned by the
/// allocator at the end of probe — `PhysFrame` has no `Drop`
/// impl (freeing is explicit), so the frames leaked permanently
/// and the driver held no handle to its own scanout.
#[derive(Copy, Clone, Debug)]
pub struct ScanoutAllocation {
    pub gtt_offset: u32,
    /// Host-physical base of the contiguous surface.
    pub phys_base: u64,
    /// Buddy order of the backing block.
    pub order: u8,
    pub size_bytes: u64,
}

/// One probed Intel iGPU.
pub struct IntelGpu {
    pub gtt_mmadr: MmioRegion,
    pub gmadr: MmioRegion,
    pub chip: ChipInfo,
    /// `GMD_ID` value captured at probe time. `None` on pre-GMD
    /// generations (Gen11, Gen9), which have no such register — see
    /// `has_gmd_id` / `stage1_presence`.
    pub gmd_id: Option<u32>,
    display_device: BusDevice,
    display_cap: Cap<BusDeviceCap, Write>,
    pub active_scanout: narf_lib::sync::IrqSafeSpinLock<Option<ActiveScanout>>,
    /// Owned scanout backing, set by probe when the allocation
    /// and plane programming succeed. `None` on PTL (display
    /// gated off) or when allocation failed (logged at probe).
    pub scanout: Option<ScanoutAllocation>,
    /// Firmware still owns the display timing and GGTT backing. Device PM
    /// cannot restore this image after a D3 transition.
    pub(crate) firmware_display: bool,
    /// The same card instance installed in the DRM registry. A future PCI GT
    /// owner publishes discovery here instead of through a global device-ID map.
    pub drm_card: Option<alloc::sync::Arc<crate::drm_devfs_bridge::IntelGpuCard>>,
}

#[derive(Clone, Debug)]
pub struct ActiveScanout {
    pub width: u32,
    pub height: u32,
    pub stride_bytes: u32,
    pub gtt_offset: u32,
    /// Host-physical base of the surface (contiguous allocation),
    /// for framebuffer-console publication.
    pub phys_base: u64,
}

impl core::fmt::Debug for IntelGpu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelGpu")
            .field("chip", &self.chip)
            .field("gmd_id", &self.gmd_id)
            .finish_non_exhaustive()
    }
}

impl IntelGpu {
    /// Map BAR0 (GTTMMADR) and BAR2 (GMADR), identify the chip,
    /// run a generation-aware presence test.
    ///
    /// # Safety
    /// Caller owns BAR0 + BAR2 exclusively for the duration of probe.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, IntelGpuError> {
        let chip = chip_info_for_pci_id(device.id.vendor, device.id.device)
            .ok_or(IntelGpuError::UnknownAsic)?;

        let gtt_mmadr =
            // SAFETY: `bring_up`'s contract gives us exclusive ownership of
            // BAR0 (`GTTMMADR`); `map_bar` maps the PCI BAR `device` advertises.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe { map_bar(device, BAR_GTTMMADR) }.map_err(|_| IntelGpuError::BarMapFailed)?;
        let gmadr =
            // SAFETY: same contract grants exclusive ownership of BAR2 (`GMADR`);
            // `map_bar` maps the PCI BAR `device` advertises.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe { map_bar(device, BAR_GMADR) }.map_err(|_| IntelGpuError::BarMapFailed)?;

        // Presence smoke test, generation-aware (see
        // `stage1_presence`). Gen12+ reads the Xe-era identity
        // registers; pre-GMD Gen11/Gen9 re-reads PCI config space —
        // the GMD_ID / MTCFG_TRBLK offsets are never read on
        // Gen11/Gen9, where their values are ungrounded.
        let gmd_id = if chip.generation.has_gmd_id() {
            // SAFETY: identity-mapped MMIO.
            let gmd = unsafe { gtt_mmadr.read32(GMD_ID) };
            compiler_fence(Ordering::SeqCst);
            // SAFETY: same.
            let trblk = unsafe { gtt_mmadr.read32(MTCFG_TRBLK) };
            stage1_presence(chip.generation, Some((gmd, trblk)), 0)?
        } else {
            // PCI config-space dword 0 (vendor ID + device ID). A
            // device that has gone away answers config reads with
            // all-ones; BAR0 mapping success is already established
            // above. No MMIO semantics are invented for Gen11/Gen9.
            let config_id = narf_bus::pci::read_config32(cap, device, 0)
                .map_err(|_| IntelGpuError::DeviceGone)?;
            stage1_presence(chip.generation, None, config_id)?
        };

        Ok(Self {
            gtt_mmadr,
            gmadr,
            chip,
            gmd_id,
            display_device: *device,
            display_cap: *cap,
            active_scanout: narf_lib::sync::IrqSafeSpinLock::new(None),
            scanout: None,
            firmware_display: false,
            drm_card: None,
        })
    }

    pub(crate) fn mode_window(&self) -> ModeWindow {
        ModeWindow::new(self.gtt_mmadr, self.display_device, self.display_cap)
    }
    pub fn current_mode(&self) -> Option<ActiveScanout> {
        self.active_scanout.lock().clone()
    }

    pub fn chip_info(&self) -> ChipInfo {
        self.chip
    }

    pub(crate) fn function_addr(&self) -> narf_bus::BusAddr {
        self.display_device.addr
    }

    pub fn gmd_id(&self) -> Option<u32> {
        self.gmd_id
    }

    /// Enumerated BAR0 register-block table for this chip's
    /// generation, or an empty slice for generations the Stage-0
    /// region map doesn't cover.
    pub fn regions(&self) -> &'static [Region] {
        match self.chip.generation.region_generation() {
            Some(gen) => intel_gpu_regions::regions_for(gen),
            None => &[],
        }
    }

    /// Look up the region that contains `bar0_offset`, if any.
    pub fn region_at(&self, bar0_offset: u64) -> Option<&'static Region> {
        self.chip
            .generation
            .region_generation()
            .and_then(|gen| intel_gpu_regions::region_at(gen, bar0_offset))
    }

    /// Look up the region of a given kind.
    pub fn region_of(&self, kind: RegionKind) -> Option<&'static Region> {
        self.chip
            .generation
            .region_generation()
            .and_then(|gen| intel_gpu_regions::region_of(gen, kind))
    }
}

// ── Driver-match registration ────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<IntelGpu>> = IrqSafeSpinLock::new(None);

// KMS owns the display while its primary plane names a GEM surface. The
// console's own allocation is retained throughout, never republished as GEM.
static KMS_CONSOLE_PAUSED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static KMS_SAVED_CONSOLE: IrqSafeSpinLock<Option<narf_graphics::FbConsole>> =
    IrqSafeSpinLock::new(None);

/// Also checked inside the framebuffer view epoch: an old cached writer
/// cannot pass its admission check before pause and capture pixels after it.
pub fn kms_console_paused() -> bool {
    KMS_CONSOLE_PAUSED.load(Ordering::Acquire)
}

/// FBIOBLANK on the Intel console: `drm_fb_helper_blank` →
/// `drm_client_modeset_dpms` (Linux b90c984d), `on` being
/// `mode == DRM_MODE_DPMS_ON`. Without a KMS master the display-14 panel's
/// crtc goes off or back on; with a master nothing changes. Linux's
/// `drm_fb_helper_blank` ignores the commit's result and the fbdev ioctl
/// is synchronous here, so the transition runs as a task.
pub fn fbdev_dpms(on: bool) {
    let Some(bar) = with_controller(|gpu| gpu.gtt_mmadr) else {
        return;
    };
    if gen_of_bar(&bar) != Some(Generation::MeteorLake) {
        return;
    }
    let _ = narf_scheduler::spawn(async move {
        let _ = crate::intel_gpu_kms::console_dpms_for_bar(&bar, on).await;
    });
}

fn gen_of_bar(bar: &narf_bus::MmioRegion) -> Option<Generation> {
    with_controller(|gpu| (gpu.gtt_mmadr.phys == bar.phys).then_some(gpu.chip.generation)).flatten()
}

/// Caller holds the KMS display session, outside CONTROLLER. Pause new
/// kernel framebuffer access, drain the synchronous log writer, then wait
/// for every earlier cursor/status/draw view (including its WC fence).
/// Cancellation leaves the console paused until verified console restoration.
pub(crate) async fn kms_pause_console() {
    crate::scanout_access::replace(|| {
        if !KMS_CONSOLE_PAUSED.swap(true, Ordering::AcqRel) {
            *KMS_SAVED_CONSOLE.lock() = narf_graphics::console::GLOBAL_FB_CONSOLE.lock().take();
        }
    });
    crate::scanout_access::wait_retired().await;
}

/// Caller holds the KMS display session and has proved the original owned
/// console surface latched (or that GEM fetch never started). Failed stop
/// paths deliberately retain the paused state and saved console.
pub(crate) fn kms_resume_console() {
    crate::scanout_access::replace(|| {
        if KMS_CONSOLE_PAUSED.load(Ordering::Acquire) {
            *narf_graphics::console::GLOBAL_FB_CONSOLE.lock() = KMS_SAVED_CONSOLE.lock().take();
            KMS_CONSOLE_PAUSED.store(false, Ordering::Release);
        }
    });
}

fn log_probe(msg: &str, device: &BusDevice) {
    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "intel-gpu: {} (PCI {:04x}:{:04x})",
        msg,
        device.id.vendor,
        device.id.device,
    );
}

/// Lunar Lake display 20 console handoff (§17 10.5), the MTL probe pattern:
/// allocate an owned console in the Pipe-A console window and point the
/// route's lit primary at it. Its GGTT entries use the PAT index of the
/// firmware's own lit surface, which must be 0
/// (`intel_gpu_xe2lpd::console_pat`). A refusal before the allocation keeps
/// the firmware surface and installs no KMS owner; a plane-build failure
/// after it retains the allocation, as the MTL path does.
fn lnl_console_handoff(dev: &mut IntelGpu, mode: &crate::intel_gpu_modeset::Mode) -> bool {
    let pat = {
        let window = dev.mode_window();
        firmware_console_pat(&crate::intel_gpu_xe2lpd::Flushed(&window))
    };
    route_console_handoff(dev, mode, pat)
}

/// The Panther Lake display-30 console handoff: the Lunar Lake pattern
/// (`lnl_console_handoff`) through the display-30 view, whose reads take
/// Wa_15015404425's flush only when `flush` (`intel_gpu_xe3lpd::
/// wa_15015404425`). PTL's GT owner programs `xe3_lpg_pat_table`, whose
/// PAT0 matches Xe2's.
fn ptl_console_handoff(
    dev: &mut IntelGpu,
    mode: &crate::intel_gpu_modeset::Mode,
    flush: bool,
) -> bool {
    let pat = {
        let window = dev.mode_window();
        firmware_console_pat(&crate::intel_gpu_xe3lpd::View::new(&window, flush))
    };
    route_console_handoff(dev, mode, pat)
}

/// The Nova Lake-S display-35 console handoff: the Lunar Lake pattern
/// (`lnl_console_handoff`) through the display-35 view, after the owned
/// route's in-place takeover. Nova's graphics 30.03-30.05 takes Linux's
/// `xe3_lpg_pat_table` (`xe_pat_init_early`, graphics 30), whose PAT0 is
/// Xe2's, and the surface's PTEs are Xe2's.
fn nvl_console_handoff(dev: &mut IntelGpu, mode: &crate::intel_gpu_modeset::Mode) -> bool {
    let pat = {
        let window = dev.mode_window();
        firmware_console_pat(&crate::intel_gpu_xe3plpd::View(&window))
    };
    route_console_handoff(dev, mode, pat)
}

/// The PAT index of the firmware's lit Pipe-A surface PTE, which the owned
/// console must reuse (`intel_gpu_xe2lpd::console_pat`); `None` refuses.
fn firmware_console_pat(io: &impl crate::intel_gpu_aux::MmioWindow) -> Option<u8> {
    use crate::intel_gpu_pipes::{Pipe, PLANE_PRIMARY_OFFSET, PLANE_SURF_OFFSET};
    let plane_base = Pipe::A.base() + PLANE_PRIMARY_OFFSET;
    let surf = io.read32(plane_base + PLANE_SURF_OFFSET);
    if surf == u32::MAX {
        return None;
    }
    let pte = crate::intel_gpu_gtt::GGTT_ARRAY_BASE + u64::from(surf >> 12) * 8;
    let (low, high) = (io.read32(pte), io.read32(pte + 4));
    crate::intel_gpu_xe2lpd::console_pat(crate::intel_gpu_xe2lpd::firmware_pte_pat(low, high))
}

/// The owned console of a display route at the firmware surface's `pat`.
fn route_console_handoff(
    dev: &mut IntelGpu,
    mode: &crate::intel_gpu_modeset::Mode,
    pat: Option<u8>,
) -> bool {
    use crate::intel_gpu_pipes::{
        Pipe, PLANE_CTL_OFFSET, PLANE_OFFSET_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_SIZE_OFFSET,
        PLANE_STRIDE_OFFSET, PLANE_SURF_OFFSET,
    };
    let plane_base = Pipe::A.base() + PLANE_PRIMARY_OFFSET;
    let Some(pat) = pat else {
        return false;
    };
    let width = u32::from(mode.h_active);
    let height = u32::from(mode.v_active);
    let stride_bytes = padded_stride_bytes(width);
    let size_bytes = scanout_size_bytes(width, height);
    let Ok(alloc) = crate::intel_gpu_gtt::alloc_contiguous_scanout_with_format(
        &dev.gtt_mmadr,
        crate::intel_gpu_gtt::SCANOUT_GTT_OFFSET_PIPE_A,
        size_bytes,
        crate::intel_gpu_gtt::PteFormat::Xe2,
        pat,
    ) else {
        return false;
    };
    let phys_base = alloc.phys_base();
    dev.scanout = Some(ScanoutAllocation {
        gtt_offset: alloc.gtt_offset,
        phys_base,
        order: alloc.order,
        size_bytes: alloc.size_bytes,
    });
    let Ok(prog) = crate::intel_gpu_pipes::build_primary_plane(
        width as u16,
        height as u16,
        stride_bytes,
        alloc.gtt_offset,
        crate::intel_gpu_pipes::PixelFormat::Argb8888,
    ) else {
        return false;
    };
    // SAFETY: `dev.gtt_mmadr` is the BAR0 region mapped in `bring_up` and
    // this probe owns the function; each offset is a Pipe A primary-plane
    // register, written in the MTL probe's order with SURF last.
    unsafe {
        dev.gtt_mmadr
            .write32(plane_base + PLANE_STRIDE_OFFSET, prog.plane_stride);
        dev.gtt_mmadr
            .write32(plane_base + PLANE_SIZE_OFFSET, prog.plane_size);
        dev.gtt_mmadr
            .write32(plane_base + PLANE_OFFSET_OFFSET, prog.plane_offset);
        dev.gtt_mmadr
            .write32(plane_base + PLANE_CTL_OFFSET, prog.plane_ctl);
        dev.gtt_mmadr
            .write32(plane_base + PLANE_SURF_OFFSET, prog.plane_surf);
    }
    compiler_fence(Ordering::SeqCst);
    *dev.active_scanout.lock() = Some(ActiveScanout {
        width,
        height,
        stride_bytes,
        gtt_offset: alloc.gtt_offset,
        phys_base,
    });
    true
}

static LNL_BOOT_SCANOUT_EXCLUSION: narf_lib::sync::IrqSafeSpinLock<Option<fn() -> bool>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Install once during trusted early framebuffer initialization. The callback
/// permanently closes boot-framebuffer/console admission before returning
/// true; sampling an empty query is insufficient. Independently owned later
/// scanouts cannot target this unadmitted LNL display. Default is refusal. No lock is
/// held while invoking it and no IRQ-safe guard survives an asynchronous wait.
pub fn install_lnl_boot_scanout_exclusion(check: fn() -> bool) {
    let mut hook = LNL_BOOT_SCANOUT_EXCLUSION.lock();
    assert!(hook.is_none(), "LNL boot scanout exclusion installed twice");
    *hook = Some(check);
}
pub(crate) fn lnl_boot_scanout_excluded() -> bool {
    let hook = *LNL_BOOT_SCANOUT_EXCLUSION.lock();
    hook.is_some_and(|check| check())
}

/// A display-less integrated GT may reserve its private GGTT arena only when
/// no firmware display fetch can still refer to an unowned GGTT entry. Both
/// PIPECONF bits must be clear on every pipe: ENABLE is the requested state,
/// while STATE can remain set while hardware drains a disable. An unavailable
/// register reads all ones and therefore refuses admission.
fn display_fetchers_stopped(io: &(impl crate::intel_gpu_aux::MmioWindow + ?Sized)) -> bool {
    if !io.display_access_ok() {
        return false;
    }
    let pipeconf = core::array::from_fn(|index| {
        use crate::intel_gpu_pipes::{Pipe, PIPECONF_OFFSET};
        let pipe = [Pipe::A, Pipe::B, Pipe::C, Pipe::D][index];
        io.read32(pipe.base() + PIPECONF_OFFSET)
    });
    display_fetchers_stopped_values(pipeconf)
}

/// Every enabled universal plane and cursor of a Gen9/Gen11 display fetches
/// from GGTT below the GT arena ([`planes_below_arena`]): three pipes of up to
/// seven planes (Ice Lake), no DSB.
fn legacy_planes_below_arena(io: &(impl crate::intel_gpu_aux::MmioWindow + ?Sized)) -> bool {
    planes_below_arena(io, 3, 7, false)
}

/// Every enabled universal plane and cursor on the first `pipes` pipes
/// (`planes` universal planes each, the source inventory) fetches from GGTT
/// below the GT arena, with room left for a 64 MiB surface, and with `dsb`
/// no display state buffer is running that could re-point one. A GT owner,
/// which writes GGTT entries only from the arena up, then cannot alias a
/// live firmware scanout. Absent registers read all ones and refuse.
pub(crate) fn planes_below_arena(
    io: &(impl crate::intel_gpu_aux::MmioWindow + ?Sized),
    pipes: usize,
    planes: u64,
    dsb: bool,
) -> bool {
    use crate::intel_gpu_pipes::{
        Pipe, PLANE_CTL_ENABLE, PLANE_CTL_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_SURF_OFFSET,
    };
    if !io.display_access_ok() {
        return false;
    }
    let limit = crate::intel_gpu_rcs::GGTT_ARENA_BASE - (64 << 20);
    [Pipe::A, Pipe::B, Pipe::C, Pipe::D]
        .into_iter()
        .take(pipes)
        .all(|pipe| {
            let base = pipe.base();
            let planes = (0..planes).all(|id| {
                let plane = base + PLANE_PRIMARY_OFFSET + id * 0x100;
                let ctl = io.read32(plane + PLANE_CTL_OFFSET);
                ctl != u32::MAX
                    && (ctl & PLANE_CTL_ENABLE == 0
                        || io.read32(plane + PLANE_SURF_OFFSET) & !0xfff < limit)
            });
            // DSB_CTRL (intel_dsb_regs.h): DSB_ENABLE or DSB_STATUS_BUSY.
            let dsb_idle = !dsb
                || (0..3).all(|id| io.read32(base + 0xb08 + id * 0x100) & ((1 << 31) | 1) == 0);
            // CURCNTR's MCURSOR_MODE_MASK, then CURBASE.
            planes
                && dsb_idle
                && (io.read32(base + 0x80) & 0x27 == 0 || io.read32(base + 0x84) & !0xfff < limit)
        })
}

/// Universal planes per pipe on a Gen12 or Xe-LPG desktop display
/// (intel_display_device.c): Tiger Lake's display 12 has six sprites, display
/// 13 and 14 four.
fn desktop_planes(platform: crate::intel_gpu_gt::GtPlatform) -> Option<u64> {
    use crate::intel_gpu_gt::{Gen12Platform, GtPlatform};
    match platform {
        GtPlatform::Gen12(Gen12Platform::TigerLake) => Some(7),
        GtPlatform::Gen12(Gen12Platform::Dg1) => None,
        GtPlatform::Gen12(_) | GtPlatform::Integrated(Generation::MeteorLake) => Some(5),
        _ => None,
    }
}

const fn display_fetchers_stopped_values(pipeconf: [u32; 4]) -> bool {
    use crate::intel_gpu_pipes::{PIPECONF_ENABLE, PIPECONF_STATE};
    let busy = PIPECONF_ENABLE | PIPECONF_STATE;
    pipeconf[0] & busy == 0
        && pipeconf[1] & busy == 0
        && pipeconf[2] & busy == 0
        && pipeconf[3] & busy == 0
}

#[path = "intel_gpu_firmware_display.rs"]
mod firmware_display;
pub(crate) use firmware_display::FirmwareRenderHandoff;

/// Fixed-mode KMS over a retained firmware framebuffer, for owners outside
/// this module (the Nova Lake-S display-35 route).
pub(crate) fn firmware_fixed_mode_card(
    fb: narf_graphics_driver::generic::GenericFb,
) -> crate::drm::card::Card {
    firmware_display::fixed_mode_card(fb)
}

/// The boot framebuffer when it is the Nova Lake-S firmware primary: the
/// same size and pitch at 32 bpp in an XRGB/ARGB layout, with the primary's
/// GGTT surface wholly below the GT arena, which can then never alias it.
fn nvl_boot_framebuffer(
    primary: &crate::intel_gpu_xe3plpd::FirmwarePrimary,
) -> Option<narf_graphics_driver::generic::GenericFb> {
    use crate::drm::card::PixelFormat;
    let fb = crate::intel_gpu_vram::boot_framebuffer()?;
    let g = primary.geometry;
    let end = u64::from(primary.gtt_offset) + u64::from(g.pitch) * u64::from(g.height);
    (matches!(
        primary.format,
        PixelFormat::Xrgb8888 | PixelFormat::Argb8888
    ) && fb.bpp == 32
        && (fb.width, fb.height, fb.pitch) == (g.width, g.height, g.pitch)
        && end <= u64::from(crate::intel_gpu_rcs::GGTT_ARENA_BASE))
    .then_some(fb)
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if device.id.vendor != INTEL_VENDOR {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    if let Some(note) = unqualified_probe_message(device.id.device) {
        log_probe(note, &device);
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    let Some(platform) =
        crate::intel_gpu_gt::GtPlatform::from_pci(device.id.vendor, device.id.device)
    else {
        log_probe(
            "unsupported Intel ASIC — device id not in the driver table",
            &device,
        );
        return Err(narf_bus::ProbeError::NotForThisDriver);
    };
    // Nova's explicit firmware route terminates here even if the live plane
    // cannot be reconstructed: PCI parking and the headless GT's driver FLR
    // would destroy the state this option exists to keep. A primary that is
    // the boot framebuffer becomes fixed-mode KMS beside a display-preserving
    // GT; anything else is only observed. With `narf.intel.nvl_modeset=1`
    // the owned display-35 takeover runs first, in place at the panel's EDID
    // mode through the LT PHY; only its success continues on the integrated
    // display path below (an owned console, KMS, suspend and relight), and
    // each refusal before its first write outside AUX keeps the firmware
    // route.
    let mut nvl_owned = None;
    if let Some(result) = crate::intel_gpu_lt_phy::probe_firmware_primary(platform, &device, &cap) {
        use core::fmt::Write as _;
        let primary = match result {
            Ok(primary) => primary,
            Err(reason) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gpu {:04x}:{:04x} firmware Pipe A readout refused ({reason:?})",
                    device.id.vendor,
                    device.id.device,
                );
                return Ok(());
            }
        };
        let Some(fb) = nvl_boot_framebuffer(&primary) else {
            let _ = writeln!(
                narf_console::Writer,
                "intel-gpu {:04x}:{:04x} firmware Pipe A {}x{} {:?}, pitch {} bytes, GGTT {:#x}",
                device.id.vendor,
                device.id.device,
                primary.geometry.width,
                primary.geometry.height,
                primary.format,
                primary.geometry.pitch,
                primary.gtt_offset,
            );
            return Ok(());
        };
        if !crate::intel_gpu_xe3plpd::modeset_requested(narf_boot::args()) {
            log_probe(
                "display 35: retaining the firmware primary for fixed-mode KMS",
                &device,
            );
            return crate::intel_gpu_gt_runtime::probe_nvl_display(device, cap, fb);
        }
        match crate::intel_gpu_xe3plpd::probe_takeover(&device, &cap, &primary) {
            Ok(mode) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gpu {:04x}:{:04x} display 35 owned eDP modeset complete on Pipe A ({}x{}, LT PHY)",
                    device.id.vendor,
                    device.id.device,
                    mode.h_active,
                    mode.v_active,
                );
                nvl_owned = Some((mode, fb));
            }
            Err(reason) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gpu {:04x}:{:04x} display 35 owned modeset refused ({reason:?}); firmware primary retained for fixed-mode KMS",
                    device.id.vendor,
                    device.id.device,
                );
                return crate::intel_gpu_gt_runtime::probe_nvl_display(device, cap, fb);
            }
        }
    }
    // Normalize every admitted Intel graphics function before any route
    // probe maps or reads BAR0. Firmware may hand an integrated or discrete
    // GPU to us in D3hot, where the transition back to D0 can clear BARs.
    // `prepare_memory_probe` restores those BARs while leaving memory decode
    // and bus mastering parked; the selected path below enables only what it
    // owns. The owned display-35 function was proved in D0 with a stable,
    // decoded BAR0 and now scans out the owned panel: parking it is skipped.
    if nvl_owned.is_none() {
        narf_bus::pci::prepare_memory_probe(&cap, &device)
            .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    }
    // A Lunar Lake function whose display-20 route is admitted (requested,
    // GMD 20.00, Pipe A fused in and lit by firmware) takes the integrated
    // display path below and never the headless profile's driver FLR;
    // every other Lunar Lake function keeps the headless profile.
    let lnl_display = crate::intel_gpu_xe2lpd::probe_route(&device, &cap);
    // The exact display-30 route (Panther Lake 30.00 with
    // `narf.intel.ptl_display=1`, or Wildcat Lake 30.02 with
    // `narf.intel.wcl_display=1`) likewise takes the integrated display path
    // and never the headless driver FLR. Without its option it reads nothing.
    let ptl_display = !lnl_display && crate::intel_gpu_xe3lpd::probe_route(&device, &cap);
    if !lnl_display
        && !ptl_display
        && nvl_owned.is_none()
        && (platform.is_discrete() || platform.is_headless_integrated())
    {
        return crate::intel_gpu_gt_runtime::probe_discrete(device, cap);
    }
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
    let mut dev = match unsafe { IntelGpu::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(e) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "intel-gpu: bring-up failed: {:?} (PCI {:04x}:{:04x})",
                e,
                device.id.vendor,
                device.id.device,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };
    // Stage-0 announce.
    {
        use core::fmt::Write as _;
        let bar0_phys = dev.gtt_mmadr.phys.raw();
        let region_count = dev.regions().len();
        // Pre-GMD generations (Gen11, Gen9) have no GMD_ID to print.
        let gmd = match dev.gmd_id {
            Some(v) => alloc::format!("{v:#010x}"),
            None => alloc::string::String::from("none"),
        };
        let _ = writeln!(
            narf_console::Writer,
            "intel-gpu: detected {} (PCI {:04x}:{:04x}, gen={:?}, GMD_ID={}) BAR0={:#018x} regions={}",
            dev.chip.asic,
            dev.chip.vid,
            dev.chip.did,
            dev.chip.generation,
            gmd,
            bar0_phys,
            region_count,
        );
    }

    // Rocket Lake's internal panel (`narf.intel.rkl_edp=1`, default off):
    // recorded before the VBT install, which it makes applicable.
    crate::intel_gpu_modeset::set_rkl_edp(
        dev.chip.generation == Generation::RocketLake
            && crate::intel_gpu_modeset::gen12_family_for_chip(dev.chip)
                == Some(crate::intel_gpu_gt::Gen12Platform::RocketLake)
            && crate::intel_gpu_modeset::rkl_edp_requested(narf_boot::args()),
    );
    // VBT (`intel_bios_init`): the ACPI OpRegion named by ASLS, read-only.
    // Installed before any external hotplug pass so the MTL port policy,
    // its legacy Type-C hotplug sources, DP SSC and the HDMI DDC pins
    // follow the board; without one every consumer keeps its no-VBT
    // behaviour.
    {
        use crate::intel_gpu_vbt::VbtInstall;
        let asls = narf_bus::pci::read_config32(&cap, &device, crate::intel_gpu_vbt::ASLS).ok();
        let gen12 = crate::intel_gpu_modeset::gen12_family_for_chip(dev.chip);
        let note = match crate::intel_gpu_vbt::install_for_probe(dev.chip.generation, gen12, asls) {
            VbtInstall::NotApplicable => None,
            VbtInstall::Missing => Some("no VBT found in the ACPI OpRegion; using defaults"),
            VbtInstall::Installed(_) => Some("VBT parsed from the ACPI OpRegion and installed"),
            VbtInstall::Refused(_) => Some("VBT found but refused: outputs already owned"),
        };
        if let Some(note) = note {
            log_probe(note, &device);
        }
    }

    // DMC firmware load (`intel_dmc_init`): the Gen12 display
    // loads its DMC blob before the first modeset, so the DC
    // states the program enables are available to runtime PM.
    // Non-fatal — a missing or malformed blob only disables
    // runtime PM; the load logs its own outcome and the probe
    // continues to modeset either way.
    if let Some(family) = crate::intel_gpu_modeset::gen12_family_for_chip(dev.chip) {
        let window = dev.mode_window();
        let authority: Option<Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>> =
            narf_firmware::trusted_loader_authority().and_then(|write| write.derive().ok());
        match authority {
            Some(authority) => {
                let _ = crate::intel_gpu_gen12_dmc::load_for_display(&window, family, &authority);
            }
            None => {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gpu: no usable firmware registry authority; DMC not loaded, runtime power management disabled"
                );
            }
        }
    }

    // Gen11 DMC load (Lane 5): the same `intel_dmc_init` shape
    // for `i915/icl_dmc_ver1_09.bin` — best-effort, non-fatal,
    // and independent of the modeset (DMC gates DC5/DC6 entry,
    // not first light). A missing or malformed blob only
    // disables runtime PM; the load logs its own outcome and
    // the probe continues to modeset either way.
    if let Some(platform) = crate::intel_gpu_modeset::gen11_family_for_chip(dev.chip) {
        let window = dev.mode_window();
        let authority: Option<Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>> =
            narf_firmware::trusted_loader_authority().and_then(|write| write.derive().ok());
        match authority {
            Some(authority) => {
                let _ = crate::intel_gpu_gen11_dmc::load_for_display(&window, platform, &authority);
            }
            None => {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gpu: no usable firmware registry authority; DMC not loaded, runtime power management disabled"
                );
            }
        }
    }

    // Gen9 DMC load (Lane 5): the same `intel_dmc_init` shape
    // for `i915/skl_dmc_ver1_27.bin` / `i915/kbl_dmc_ver1_04.bin`
    // — but REQUIRED, not best-effort (the Q5 default,
    // mirroring Gen12): a failed load leaves the installed flag
    // clear and the display modeset refuses with
    // `ModesetError::DmcUnavailable`. The probe itself continues
    // either way (GT / execlists still bind); the load logs its
    // own outcome.
    if let Some(platform) = crate::intel_gpu_modeset::gen9_family_for_chip(dev.chip) {
        // Gen9 DC states (`narf.intel.gen9_dc=1`, default off): the
        // `DC_off` service disables DC states and holds them off from here
        // to the end of probe (`skl_display_core_init`'s DC_STATE_DISABLE,
        // `POWER_DOMAIN_INIT`). Without the option nothing is written.
        crate::intel_gpu_gen9_dc_states::install(platform, dev.gtt_mmadr, cap);
        // Gen9 shared-DPLL arbitration between external outputs
        // (`narf.intel.gen9_dpll=1`, default off: every external output
        // takes DPLL1 without it).
        crate::intel_gpu_gen9_dpll::set_arbitration(
            !platform.is_lp()
                && crate::intel_gpu_gen9_dpll::arbitration_requested(narf_boot::args()),
        );
        let window = dev.mode_window();
        let authority: Option<Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>> =
            narf_firmware::trusted_loader_authority().and_then(|write| write.derive().ok());
        match authority {
            Some(authority) => {
                let _ = crate::intel_gpu_gen9_dmc::load_for_display(&window, platform, &authority);
            }
            None => {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gpu: no usable firmware registry authority; DMC not loaded, display modeset refused"
                );
            }
        }
    }

    let external_only =
        crate::intel_gpu_modeset::gen12_family_for_chip(dev.chip).is_some_and(|family| {
            crate::intel_gpu_vbt::gen12_ddc_overrides().external_only_for(family)
        });
    let mut firmware_scanout = None;
    let mut panel_mode: Option<crate::intel_gpu_modeset::Mode> = None;
    if external_only {
        firmware_scanout = crate::intel_gpu_vram::boot_framebuffer().and_then(|fb| {
            let io = dev.mode_window();
            let scanout = firmware_display::scanout(&io, dev.gmadr.phys.raw(), dev.gmadr.len, fb);
            if scanout.is_none() {
                firmware_display::log_mismatch(&io, dev.gmadr.phys.raw(), fb);
            }
            scanout
        });
        dev.firmware_display = firmware_scanout.is_some();
        log_probe(
            if firmware_scanout.is_some() {
                "external-only VBT, retaining the active firmware framebuffer for fixed-mode KMS"
            } else {
                "external-only VBT, no active linear firmware primary matched the boot framebuffer"
            },
            &device,
        );
    } else if crate::intel_gpu_modeset::panel_route(dev.chip.generation)
        && (dev.chip.generation != Generation::RocketLake || rkl_panel_declared())
    {
        // eDP panel power sequencing (#1020): the panel must be
        // sequenced on before any AUX traffic (the EDID read
        // inside takeover), modeset, or backlight enable. A
        // panel that fails its sequence is left powered-down:
        // no backlight install, no takeover, no scanout move.
        let window = crate::intel_gpu_edp::BarWindow(&dev.gtt_mmadr);
        // Gen9 LP has no PCH: its power sequencer is in the display engine,
        // and the eDP port's AUX channel needs the port's DPIO PHY powered
        // (Linux powers every PHY at display init).
        let lp = dev.chip.generation == Generation::Broxton;
        if lp {
            use crate::intel_gpu_bxt_phy::Port;
            let glk = dev.chip.asic == "geminilake";
            for port in [Port::A, Port::B, Port::C] {
                if crate::intel_gpu_bxt_display::power_port(&window, glk, port).is_err() {
                    log_probe("a DDI's PHY did not power up", &device);
                }
            }
        }
        let pps_window = crate::intel_gpu_bxt_display::PpsWindow::new(&window, lp);
        // intel_pps_get_registers: a display-9 panel on a pre-CNP south
        // display (SPT/KBP) keeps its power-cycle delay in PP_DIVISOR.
        // Programmed only with narf.intel.pp_divisor=1.
        let divisor = crate::intel_gpu_edp::pp_divisor_for(
            dev.chip.generation == Generation::Skylake
                && crate::intel_gpu_edp::pp_divisor_requested(narf_boot::args()),
            {
                use crate::intel_gpu_aux::MmioWindow as _;
                dev.mode_window()
                    .gen12_hpd_profile()
                    .is_some_and(|profile| profile.has_pp_divisor())
            },
            &window,
        );
        let mut pps =
            crate::intel_gpu_edp::PanelPowerSequencer::new_with_divisor(&pps_window, divisor);
        pps.init_registers();
        crate::intel_gpu_edp::runtime_install_panel(
            pps.delays(),
            crate::intel_gpu_edp::PsrLayout::from_generation(dev.chip.generation),
        );
        crate::intel_gpu_edp::runtime_install_divisor(divisor);
        let panel_on = match pps.power_on() {
            Ok(()) => true,
            Err(e) => {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gpu: eDP panel power sequence failed: {:?} — panel left powered down, display skipped",
                    e,
                );
                false
            }
        };

        // Take over the firmware display. The takeover modeset
        // programs the plane at the GOP surface; probe then moves
        // scanout to the owned allocation below — the second
        // plane programming is deliberate (dropping it would
        // leave `active_scanout` naming a buffer the plane is
        // not scanning), but it no longer panics and it logs
        // each failing step instead of collapsing to silence.
        let mode_opt = if panel_on {
            // Activate backlight PWM where the generation's PWM
            // block is modelled (Gen12 today; MTL's install is
            // gated on the backlight composition lane, PR #1037).
            // Gen9 Skylake drives the SPT PWM layout, Gen11/Gen12
            // the BXT layout (Lane 8).
            // Gen9 LP's backlight controller is the BXT layout itself.
            // Rocket Lake's panel (`narf.intel.rkl_edp=1`) takes the CNP PWM
            // (`cnp_pwm_funcs`, the BXT-layout block the Gen12 install drives).
            if dev.chip.generation.backlight_supported()
                || dev.chip.generation == Generation::RocketLake
            {
                if dev.chip.generation == Generation::Skylake {
                    narf_drivers_backlight::intel_bl::install_spt(dev.gtt_mmadr);
                } else if dev.chip.generation == Generation::Broxton {
                    narf_drivers_backlight::intel_bl::install_bxt(
                        dev.gtt_mmadr,
                        crate::intel_gpu_vbt::gen9_lp().backlight_controller,
                    );
                } else {
                    narf_drivers_backlight::intel_bl::install(dev.gtt_mmadr);
                }
            }
            let mode = crate::intel_gpu_modeset::takeover_display(&dev);
            if mode.is_some() {
                // The PPS backlight gate opens only with live
                // video; T8 runs from the power-on stamp inside
                // the sequencer.
                let _ = pps.backlight_on();
            }
            mode
        } else {
            None
        };
        panel_mode = mode_opt;

        // The internal display owns Pipe A from here on
        // (#1017): external sessions arbitrate the remaining
        // pipes through `intel_gpu_multipipe` instead of
        // silently sharing this one. Claimed only when a
        // firmware pipeline was actually taken over — with no
        // internal display live, Pipe A stays free for the
        // first external session, as before multi-pipe support.
        if mode_opt.is_some() {
            let _ = crate::intel_gpu_multipipe::claim_pipe(
                crate::intel_gpu_pipes::Pipe::A,
                crate::intel_gpu_multipipe::PipeOwner {
                    ddi: crate::intel_gpu_ddi::Ddi::A,
                    used_for: crate::intel_gpu_multipipe::PipeUse::InternalPanel,
                },
            );
        }

        // A powered panel alone does not establish a scanning pipeline.
        // Allocate and publish only after takeover returned an actual mode.
        if let Some(mode) = mode_opt {
            let width = u32::from(mode.h_active);
            let height = u32::from(mode.v_active);
            let stride_bytes = padded_stride_bytes(width);
            let size_bytes = scanout_size_bytes(width, height);

            match crate::intel_gpu_gtt::alloc_contiguous_scanout(&dev.gtt_mmadr, size_bytes) {
                Ok(alloc) => {
                    let phys_base = alloc.phys_base();
                    dev.scanout = Some(ScanoutAllocation {
                        gtt_offset: alloc.gtt_offset,
                        phys_base,
                        order: alloc.order,
                        size_bytes: alloc.size_bytes,
                    });
                    match crate::intel_gpu_pipes::build_primary_plane(
                        width as u16,
                        height as u16,
                        stride_bytes,
                        alloc.gtt_offset,
                        crate::intel_gpu_pipes::PixelFormat::Argb8888,
                    ) {
                        Ok(prog) => {
                            let plane_base = crate::intel_gpu_pipes::Pipe::A.base()
                                + crate::intel_gpu_pipes::PLANE_PRIMARY_OFFSET;
                            // SAFETY: `dev.gtt_mmadr` is the BAR0 region mapped in
                            // `bring_up`, and we own the device. `plane_base` is
                            // Pipe A's primary plane block; every offset is a
                            // known in-range plane register.
                            // SAFETY: Valid MMIO bounds or trusted driver environment
                            unsafe {
                                dev.gtt_mmadr.write32(
                                    plane_base + crate::intel_gpu_pipes::PLANE_STRIDE_OFFSET,
                                    prog.plane_stride,
                                );
                                dev.gtt_mmadr.write32(
                                    plane_base + crate::intel_gpu_pipes::PLANE_SIZE_OFFSET,
                                    prog.plane_size,
                                );
                                dev.gtt_mmadr.write32(
                                    plane_base + crate::intel_gpu_pipes::PLANE_OFFSET_OFFSET,
                                    prog.plane_offset,
                                );
                                dev.gtt_mmadr.write32(
                                    plane_base + crate::intel_gpu_pipes::PLANE_CTL_OFFSET,
                                    prog.plane_ctl,
                                );
                                dev.gtt_mmadr.write32(
                                    plane_base + crate::intel_gpu_pipes::PLANE_SURF_OFFSET,
                                    prog.plane_surf,
                                );
                            }
                            compiler_fence(Ordering::SeqCst);
                            *dev.active_scanout.lock() = Some(ActiveScanout {
                                width,
                                height,
                                stride_bytes,
                                gtt_offset: alloc.gtt_offset,
                                phys_base,
                            });
                        }
                        Err(e) => {
                            use core::fmt::Write as _;
                            let _ = writeln!(
                            narf_console::Writer,
                            "intel-gpu: primary-plane build failed: {:?} ({}x{} stride {}) — scanout allocated but plane not reprogrammed",
                            e, width, height, stride_bytes,
                        );
                        }
                    }
                }
                Err(e) => {
                    use core::fmt::Write as _;
                    let _ = writeln!(
                    narf_console::Writer,
                    "intel-gpu: scanout allocation failed: {:?} ({}x{} padded stride {}, {} bytes) — display left on firmware surface",
                    e, width, height, stride_bytes, size_bytes,
                );
                }
            }
        }
    } else if lnl_display {
        // Lunar Lake display 20 (Xe2_LPD), admitted per device: sequence
        // the eDP panel, then run the display-20 owned modeset on the
        // firmware's Pipe-A surface. The console then moves to an owned
        // surface mapped at the firmware surface's own PAT index (the MTL
        // pattern; `lnl_console_handoff`), which installs the display-20
        // KMS owner below. A refused handoff leaves the firmware surface
        // and no KMS owner. No PM owner is installed: the GT owner, with
        // the display-preserving profile, is D0-only. The whole window
        // (sequencer, modeset, backlight gate) reads through
        // Wa_15015404425's dummy writes (`probe_window`).
        let window = crate::intel_gpu_edp::BarWindow(&dev.gtt_mmadr);
        let mode = match crate::intel_gpu_xe2lpd::probe_window(&window, &dev.mode_window(), |io| {
            crate::intel_gpu_xe2lpd::takeover(io)
        }) {
            Ok(mode) => mode,
            Err(e) => {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gpu: eDP panel power sequence failed: {:?} — display 20 skipped",
                    e,
                );
                None
            }
        };
        if let Some(mode) = mode.as_ref() {
            let _ = crate::intel_gpu_multipipe::claim_pipe(
                crate::intel_gpu_pipes::Pipe::A,
                crate::intel_gpu_multipipe::PipeOwner {
                    ddi: crate::intel_gpu_ddi::Ddi::A,
                    used_for: crate::intel_gpu_multipipe::PipeUse::InternalPanel,
                },
            );
            log_probe(
                "display 20 (Xe2_LPD) owned eDP modeset complete on Pipe A",
                &device,
            );
            log_probe(
                if lnl_console_handoff(&mut dev, mode) {
                    "display 20 console moved to an owned Pipe-A surface"
                } else {
                    "display 20 console handoff refused; firmware surface retained"
                },
                &device,
            );
        } else {
            log_probe(
                "display 20 (Xe2_LPD) takeover refused; firmware display retained",
                &device,
            );
        }
        panel_mode = mode;
    } else if ptl_display {
        // Panther/Wildcat Lake display 30 (Xe3_LPD), admitted per device: the
        // Lunar Lake sequence through the display-30 view (`intel_gpu_xe3lpd::
        // View`: PICA-relocated DDI A PHY/AUX registers, the display-30 Cx0
        // dialect, and Wa_15015404425's flush only before media B0).
        let window = crate::intel_gpu_edp::BarWindow(&dev.gtt_mmadr);
        let flush = crate::intel_gpu_xe3lpd::wa_15015404425_active(&window);
        let mode =
            match crate::intel_gpu_xe3lpd::probe_window(&window, &dev.mode_window(), flush, |io| {
                crate::intel_gpu_xe3lpd::takeover(io)
            }) {
                Ok(mode) => mode,
                Err(e) => {
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "intel-gpu: eDP panel power sequence failed: {:?} — display 30 skipped",
                        e,
                    );
                    None
                }
            };
        if let Some(mode) = mode.as_ref() {
            let _ = crate::intel_gpu_multipipe::claim_pipe(
                crate::intel_gpu_pipes::Pipe::A,
                crate::intel_gpu_multipipe::PipeOwner {
                    ddi: crate::intel_gpu_ddi::Ddi::A,
                    used_for: crate::intel_gpu_multipipe::PipeUse::InternalPanel,
                },
            );
            log_probe(
                "display 30 (Xe3_LPD) owned eDP modeset complete on Pipe A",
                &device,
            );
            log_probe(
                if ptl_console_handoff(&mut dev, mode, flush) {
                    "display 30 console moved to an owned Pipe-A surface"
                } else {
                    "display 30 console handoff refused; firmware surface retained"
                },
                &device,
            );
        } else {
            log_probe(
                "display 30 (Xe3_LPD) takeover refused; firmware display retained",
                &device,
            );
        }
        panel_mode = mode;
    } else if let Some((mode, fb)) = nvl_owned {
        // Nova Lake-S display 35.00 (Xe3P_LPD), owned per device: the probe's
        // in-place takeover lit the eDP panel through the LT PHY. Pipe A is
        // the route's, and the console moves to an owned surface as on
        // display 30, which installs the display-35 KMS owner below. A
        // refused handoff keeps the firmware surface as fixed-mode KMS, with
        // the firmware route's GT owner (no system suspend).
        let _ = crate::intel_gpu_multipipe::claim_pipe(
            crate::intel_gpu_pipes::Pipe::A,
            crate::intel_gpu_multipipe::PipeOwner {
                ddi: crate::intel_gpu_ddi::Ddi::A,
                used_for: crate::intel_gpu_multipipe::PipeUse::InternalPanel,
            },
        );
        if nvl_console_handoff(&mut dev, &mode) {
            log_probe(
                "display 35 console moved to an owned Pipe-A surface",
                &device,
            );
        } else {
            log_probe(
                "display 35 console handoff refused; firmware surface retained for fixed-mode KMS",
                &device,
            );
            firmware_scanout = Some(fb);
            dev.firmware_display = true;
        }
        panel_mode = Some(mode);
    } else {
        // Identification is real, but this exact display family has no
        // validated programming sequence in the admitted path yet.
        log_probe(
            "display programming skipped — exact display family is not admitted",
            &device,
        );
    }

    // The qualified full-AUX MTL owner is installed only after actual mode,
    // retained scanout and the internal Pipe-A claim exist. Other profiles
    // keep their existing backlight mechanism; no MTL PWM gate is widened.
    crate::intel_dpcd_bl::install_mtl(&dev, device, cap);

    // PSR bring-up (#1020): only for an eDP panel that powered
    // on and produced a real mode. Every failure path inside
    // leaves the panel running plain eDP. Display 14 PSR is not
    // the Gen12 register layout: it is enabled only by the KMS owner
    // (`intel_gpu_psr`), never on the console. Gen11 PSR is
    // excluded too (Lane 5): the display-11 PSR layout is
    // unverified — `PsrLayout::from_generation` falls back to
    // the TigerLake table for IceLake, and the stored layout is
    // inert until a lane grounds the real one — so the panel
    // runs plain eDP. Gen9 PSR is excluded for the same reason
    // (Gen9 Lane 5): `PsrLayout::from_generation` falls back
    // to the TigerLake table for Skylake too, and programming
    // the TGL-layout PSR registers on SKL silicon is not a
    // modeset this lane can stand behind.
    if let Some(mode) = panel_mode.filter(|_| {
        dev.chip.generation.display_supported()
            && dev.chip.generation != Generation::MeteorLake
            && dev.chip.generation != Generation::IceLake
            && dev.chip.generation != Generation::Skylake
            && dev.chip.generation != Generation::Broxton
    }) {
        crate::intel_gpu_edp::enable_psr_for_panel(&dev, &mode);
    }

    // Media-engine inventory (#1022): announce exactly the
    // execlists media engines the submission path can drive
    // on this part — the same list `intel_gpu_media` attaches
    // lazily on first submit.
    if let Some(rg) = dev.chip_info().generation.region_generation() {
        let engines = crate::intel_gpu_media::media_engines_for(rg);
        if !engines.is_empty() {
            let mut names = alloc::string::String::new();
            for (i, spec) in engines.iter().enumerate() {
                if i > 0 {
                    names.push(' ');
                }
                names.push_str(spec.name);
            }
            log_probe(&alloc::format!("media engines present: {}", names), &device);
        }
    }

    let scanout_mode = dev.current_mode();
    // A Meteor/Arrow Lake, Ice Lake or Skylake-class board with no owned
    // panel (a desktop, or a panel takeover that failed) still scanning the
    // GOP framebuffer: retain it for fixed-mode KMS, as an external-only
    // Gen12 board does, and keep hotplug modesets and system suspend off the
    // inherited pipe. Broxton and Gemini Lake take this route too when no
    // panel is owned. Displays 9 to 11
    // have three pipes, with Skylake's universal-plane registers. On
    // Gen9/Gen11 the execlists owner already starts beside it (its planes
    // fetch below the GT arena); Meteor Lake's GuC owner takes the firmware
    // handoff below.
    let fixed_pipes = match dev.chip.generation {
        Generation::MeteorLake => Some(4),
        Generation::IceLake | Generation::Skylake | Generation::Broxton => Some(3),
        _ => None,
    };
    if let Some(pipes) =
        fixed_pipes.filter(|_| firmware_scanout.is_none() && scanout_mode.is_none())
    {
        firmware_scanout = crate::intel_gpu_vram::boot_framebuffer().and_then(|fb| {
            firmware_display::scanout_on(
                &dev.mode_window(),
                dev.gmadr.phys.raw(),
                dev.gmadr.len,
                fb,
                pipes,
            )
        });
        if firmware_scanout.is_some() {
            dev.firmware_display = true;
            log_probe(
                "no owned panel, retaining the active firmware framebuffer for fixed-mode KMS",
                &device,
            );
        }
    }
    let kms_console = scanout_mode.clone();
    let kms_generation = dev.chip.generation;
    let platform = crate::intel_gpu_gt::GtPlatform::from_pci(device.id.vendor, device.id.device);
    // A desktop/headless Gen12 or Xe-LPG system has no owned scanout to
    // authorize GT startup. It can still run compute safely when every
    // display fetcher proves stopped: the GT arena begins at 256 MiB and no
    // live firmware plane can refer to an unowned GGTT entry. Keep this
    // separate from LNL/PTL, whose headless profile requires a driver FLR.
    let firmware_handoff = firmware_scanout.and_then(|fb| {
        if dev.chip.generation == Generation::MeteorLake {
            return FirmwareRenderHandoff::discover_display14(
                &dev.mode_window(),
                dev.gmadr.phys.raw(),
                dev.gmadr.len,
                fb,
            );
        }
        let family = crate::intel_gpu_modeset::gen12_family_for_chip(dev.chip)?;
        FirmwareRenderHandoff::discover(
            family,
            &dev.mode_window(),
            dev.gmadr.phys.raw(),
            dev.gmadr.len,
            fb,
        )
    });
    // The Gen9/Gen11 execlists owner touches only GT registers and its GGTT
    // arena from 256 MiB, and its full-domain GT reset leaves the display
    // alone. It coexists with a lit firmware display whose planes all fetch
    // below the arena.
    let execlists_gt = platform
        .and_then(crate::intel_gpu_legacy_gt::LegacyGt::for_platform)
        .is_some()
        && legacy_planes_below_arena(&dev.mode_window());
    let stopped_display_gt = scanout_mode.is_none()
        && platform.is_some_and(|platform| {
            (platform.is_gen12()
                || platform == crate::intel_gpu_gt::GtPlatform::Integrated(Generation::MeteorLake))
                && display_fetchers_stopped(&dev.mode_window())
        });
    // A Gen12 or Meteor/Arrow Lake desktop whose GOP-lit display matches no
    // firmware handoff (several outputs, a tiled or offset surface, Arrow
    // Lake): the GuC owner's arena starts at 256 MiB, so it coexists with a
    // display whose every plane and cursor fetches below it and whose DSBs
    // are idle. The firmware display stays as it is; no KMS owner installs.
    let below_arena_gt = scanout_mode.is_none()
        && firmware_handoff.is_none()
        && platform
            .and_then(desktop_planes)
            .is_some_and(|planes| planes_below_arena(&dev.mode_window(), 4, planes, true));
    // Power management (Q9, #1015) covers the Gen12 register
    // map only. Xe-LPG now has a region map and a display
    // engine (#1016); its separate GT owner handles system PM below.
    // A Gen12 function with an owned scanout uses the async GuC owner below.
    // The legacy PM owner remains only on identity/inherited-scanout fallback.
    let pm_supported = dev.chip.generation.display_supported()
        && matches!(
            dev.chip.generation.region_generation(),
            Some(RegionGeneration::Gen12)
        );
    // Register with drm_registry. With a live scanout the card
    // carries real KMS mode state (CRTC 1 + mode, encoder 2,
    // eDP connector 3 — the virtio/bochs pattern in lib.rs) and
    // the scanout is published to the framebuffer console;
    // without one (PTL gate, allocation failure) the card
    // stays identity-only, as before lane 1.
    let drm_count = crate::drm_registry::count() as u32;
    let card_name = alloc::format!("card{}", drm_count);
    let intel_card = alloc::sync::Arc::new(crate::drm_devfs_bridge::IntelGpuCard::new(
        card_name,
        device.id.vendor,
        device.id.device,
        device.id.subsystem_vendor,
        device.id.subsystem_id,
    ));
    dev.drm_card = Some(intel_card.clone());
    let gt_card = intel_card.clone();
    let gt_bar = dev.gtt_mmadr;
    *CONTROLLER.lock() = Some(dev);
    let owns_scanout = scanout_mode.is_some();
    let card_index = match scanout_mode {
        Some(mode) => {
            use crate::drm::card::{
                Card, Connector, ConnectorStatus, ConnectorType, Crtc, Encoder, EncoderType,
                NativeOutput,
            };
            let kms_mode = crate::Mode {
                width: mode.width,
                height: mode.height,
                refresh_hz: 60,
                bpp: 32,
            };
            let mut kms = Card::new("intel-gpu", "NARF Intel iGPU driver", (1, 0, 0));
            kms.crtcs.push(Crtc {
                id: 1,
                mode: Some(kms_mode),
                enabled: true,
                primary_fb: None,
                x: 0,
                y: 0,
            });
            kms.vrr_enabled.push((1, false));
            kms.encoders.push(Encoder {
                id: 2,
                // i915 reports DP encoders as TMDS to userspace.
                encoder_type: EncoderType::Tmds,
                possible_crtcs: 0x1,
                possible_clones: 0,
                crtc_id: Some(1),
            });
            kms.connectors.push(Connector {
                id: 3,
                connector_type: ConnectorType::Edp,
                connector_type_id: 1,
                status: ConnectorStatus::Connected,
                encoder_id: Some(2),
                modes: alloc::vec![kms_mode],
            });
            kms.native.push(NativeOutput {
                connector: 3,
                edid: None,
                timings: alloc::vec::Vec::new(),
                color_format: None,
                broadcast_rgb: Some(0),
                // Unknown until the panel's EDID/DPCD discovery runs:
                // the old hardcoded `Some(true)` claimed VRR for a
                // sink whose range no one had read. `None` withholds
                // the `vrr_capable` property until discovery publishes
                // the range (DP: `probe_sink`; the panel range is
                // published by eDP discovery).
                vrr_capable: None,
                colorspace: Some(0),
                hdr_output_metadata: Some(0),
                max_bpc: Some(8),
            });
            let index = crate::drm_registry::register_drm_card_with_state(intel_card, kms);
            publish_scanout(Some(narf_graphics_driver::generic::GenericFb::new(
                mode.phys_base,
                mode.width,
                mode.height,
                mode.stride_bytes,
                32,
            )));
            index
        }
        None => match firmware_scanout {
            Some(fb) => crate::drm_registry::register_drm_card_with_state(
                intel_card,
                firmware_display::fixed_mode_card(fb),
            ),
            None => crate::drm_registry::register_drm_card(intel_card),
        },
    };
    if let Some(console) = kms_console {
        crate::intel_gpu_kms::install(card_index, kms_generation, gt_bar, device, cap, console);
    }
    // Display-14/20/30 DC service: an external route that stays live or
    // quarantined between hotplug passes keeps DC5/DC6 re-entry refused.
    if crate::intel_gpu_xelpg_hpd::hpd_generation_supported(kms_generation) {
        crate::intel_gpu_dc_states::register_external_live(Some(
            crate::intel_gpu_xelpg_external::external_route_blocks_dc,
        ));
    }
    // The external fixed-mode path retains the firmware surface. Its GT
    // owner independently verifies every display fetcher before using the
    // separate GGTT arena, and keeps the function powered for that surface.
    let guc_owned = if lnl_display && panel_mode.is_some() {
        crate::intel_gpu_gt_runtime::install_lnl_display(
            card_index, gt_card, device, cap, gt_bar, panel_mode,
        )
    } else if ptl_display && panel_mode.is_some() {
        crate::intel_gpu_gt_runtime::install_ptl_display(
            card_index, gt_card, device, cap, gt_bar, panel_mode,
        )
    } else if nvl_owned.is_some() {
        // The owned console is the relight owner of system suspend; a
        // retained firmware surface keeps the firmware route's profile.
        crate::intel_gpu_gt_runtime::install_nvl_display(
            card_index,
            gt_card,
            device,
            cap,
            gt_bar,
            panel_mode,
            owns_scanout,
        )
    } else if owns_scanout
        || stopped_display_gt
        || below_arena_gt
        || firmware_handoff.is_some()
        || execlists_gt
    {
        crate::intel_gpu_gt_runtime::install(
            card_index,
            gt_card,
            device,
            cap,
            gt_bar,
            panel_mode,
            firmware_handoff,
        )
    } else {
        false
    };

    if firmware_scanout.is_some() {
        log_probe(
            if guc_owned {
                "retained firmware scanout; scheduled Intel render engine startup"
            } else {
                "retained firmware scanout; render engine unavailable (display ownership or GT admission)"
            },
            &device,
        );
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("intel-gpu"),
        kind: narf_drivers::BoundKind::Graphics,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Graphics.default_domain(),
    });

    // External DP (lane Q4, #1092): program the combo-DDI HPD
    // interrupt enables and pick up a sink that was already
    // attached at boot. The session connect path re-checks the
    // generation's display support itself.
    with_controller(|gpu| {
        if !gpu.firmware_display {
            enable_external_hpd(&gpu.mode_window(), gpu.chip.generation);
        }
    });
    poll_dp_hpd_events();

    // Gen9 DC states: hardware readout is done. The Init reference drops
    // (DC5/DC6 may be entered once idle) only with the DMC loaded and the
    // internal panel owned on Pipe A; inert without the Gen9 service.
    crate::intel_gpu_gen9_dc_states::probe_complete(&gt_bar, owns_scanout && panel_mode.is_some());
    // Gen9 display system suspend (`narf.intel.gen9_suspend=1`, default
    // off): the owned panel turns off before system sleep and is relit after
    // it. Without the option nothing is installed.
    if let Some(chip) = with_controller(|gpu| gpu.chip).filter(|_| owns_scanout) {
        crate::intel_gpu_gen9_suspend::install(
            crate::intel_gpu_gen9_suspend::requested(narf_boot::args()),
            chip,
            gt_bar,
            device,
            cap,
            panel_mode,
        );
    }
    // Gen9 interrupts (`narf.intel.gen9_irq=1`, default off): the hard
    // handler and service pass for the hotplug, display and GT interrupts,
    // installed after the hotplug monitor and the display suspend owner (its
    // system-sleep preparation runs before theirs). Without the option nothing
    // is installed or written.
    if let Some(platform) =
        with_controller(|gpu| crate::intel_gpu_modeset::gen9_family_for_chip(gpu.chip)).flatten()
    {
        crate::intel_gpu_gen9_irq::install(
            crate::intel_gpu_gen9_irq::requested(narf_boot::args()),
            platform,
            gt_bar,
            device,
            cap,
        );
    }

    // Power management (Q9, #1015): retain the PCI authority,
    // note the takeover mode for resume re-light, and register
    // the device-PM + suspend-hook pair. Last, so a failed
    // probe never leaves a registration behind.
    if pm_supported && !guc_owned {
        crate::intel_gpu_pm::register_pm(device, cap, panel_mode);
    }
    Ok(())
}

/// Re-establish the display after a D3 excursion (Q9, #1015):
/// allocate a fresh scanout at `mode`'s dimensions and run
/// the real modeset at it. The GGTT PTEs behind the
/// pre-suspend surface do not survive D3, so — exactly as
/// probe does — the surface is re-allocated and the plane
/// reprogrammed, never restored in place. On success the
/// controller's scanout state and the fb-console publication
/// follow the new surface. Returns the new active scanout.
pub fn relight_display(mode: &crate::intel_gpu_modeset::Mode) -> Option<ActiveScanout> {
    let display =
        with_controller(|gpu| crate::intel_gpu_kms::display_for_bar(&gpu.gtt_mmadr)).flatten();
    let mut ownership = match display.as_ref() {
        Some(display) => Some(display.legacy().ok()?),
        None => None,
    };
    if let Some(guard) = ownership.as_mut() {
        guard.suspend();
    }
    let console = relight_display_locked(mode)?;
    if let Some(guard) = ownership.as_mut() {
        guard.console_replaced(&console);
    }
    Some(console)
}

/// The caller already holds the display's LegacyGuard. Used by the PM core
/// so its outer power-transition exclusion is retained through publication.
pub(crate) fn relight_display_locked(
    mode: &crate::intel_gpu_modeset::Mode,
) -> Option<ActiveScanout> {
    let display = with_display_info(|display| *display)?;
    let kms = crate::intel_gpu_kms::display_for_bar(&display.gtt_mmadr);
    let xe_lpd_route = matches!(
        display.chip.generation,
        Generation::LunarLake | Generation::PantherLake
    ) && kms.is_some();
    // Nova Lake-S shares the Panther Lake generation; only the KMS owner's
    // proved display 35.00 selects its LT-PHY relight.
    let nova = kms.as_ref().and_then(|kms| kms.integrated_display_ip())
        == Some(crate::intel_gpu_xe2lpd::DisplayIp::NovaLakeS);
    drop(kms);
    if !crate::intel_gpu_modeset::panel_route(display.chip.generation) && !xe_lpd_route {
        return None;
    }
    // Its relight needs the probe's sequencer delays and the panel turned off
    // before suspend: refuse before the surface is allocated otherwise.
    if nova
        && (crate::intel_gpu_xe3plpd::panel_delays().is_none()
            || crate::intel_gpu_modeset_xelpg::panel_off_record().is_none())
    {
        return None;
    }
    if !external_routes_stopped(&display.gtt_mmadr) {
        return None;
    }
    let aux_backlight = crate::intel_dpcd_bl::installed(&display.gtt_mmadr);
    if aux_backlight {
        crate::intel_dpcd_bl::prepare_relight_for_bar(&display.gtt_mmadr).ok()?;
    }
    let width = u32::from(mode.h_active);
    let height = u32::from(mode.v_active);
    let stride_bytes = padded_stride_bytes(width);
    let size_bytes = scanout_size_bytes(width, height);
    let alloc = if xe_lpd_route {
        crate::intel_gpu_gtt::alloc_contiguous_scanout_with_format(
            &display.gtt_mmadr,
            crate::intel_gpu_gtt::SCANOUT_GTT_OFFSET_PIPE_A,
            size_bytes,
            crate::intel_gpu_gtt::PteFormat::Xe2,
            0,
        )
        .ok()?
    } else {
        crate::intel_gpu_gtt::alloc_contiguous_scanout(&display.gtt_mmadr, size_bytes).ok()?
    };
    let fb = crate::intel_gpu_modeset::Framebuffer {
        phys_addr: u64::from(alloc.gtt_offset),
        stride_bytes,
        format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
    };
    let window = ModeWindow::new(display.gtt_mmadr, display.device, display.cap);
    let applied = if display.chip.generation == Generation::LunarLake {
        crate::intel_gpu_xe2lpd::modeset(&window, &fb, Some(mode)).ok()?
    } else if nova {
        // Display 35 relights the panel its suspend turned off, through the
        // LT PHY, after reprogramming the sequencer with the probe's delays.
        let delays = crate::intel_gpu_xe3plpd::panel_delays()?;
        crate::intel_gpu_xe3plpd::relight(
            &crate::intel_gpu_xe3plpd::View(&window),
            &fb,
            mode,
            delays,
        )
        .ok()?
    } else if display.chip.generation == Generation::PantherLake {
        crate::intel_gpu_xe3lpd::modeset(&window, &fb, Some(mode)).ok()?
    } else {
        crate::intel_gpu_modeset::modeset_display_for_chip(&window, display.chip, &fb, Some(mode))
            .ok()?
    };
    if xe_lpd_route {
        let ip = crate::intel_gpu_vrr::DisplayVrrIp::from_generation(display.chip.generation);
        let range = crate::intel_gpu_vrr::VRR_STATE.range(1);
        crate::intel_gpu_vrr::recompute_timings_for_modeset(
            1,
            &applied,
            range,
            ip,
            crate::intel_gpu_vrr::VrrComputeOpts::default(),
            crate::intel_gpu_vrr::VrrConnectorKind::EmbeddedDisplayPort,
        );
    }
    let scanout = ActiveScanout {
        width: u32::from(applied.h_active),
        height: u32::from(applied.v_active),
        stride_bytes,
        gtt_offset: alloc.gtt_offset,
        phys_base: alloc.phys_base(),
    };
    let mut guard = CONTROLLER.lock();
    let dev = guard.as_mut()?;
    if dev.gtt_mmadr.phys != display.gtt_mmadr.phys {
        return None;
    }
    dev.scanout = Some(ScanoutAllocation {
        gtt_offset: alloc.gtt_offset,
        phys_base: alloc.phys_base(),
        order: alloc.order,
        size_bytes: alloc.size_bytes,
    });
    *dev.active_scanout.lock() = Some(scanout.clone());
    let phys_base = scanout.phys_base;
    let (w, h) = (scanout.width, scanout.height);
    drop(guard);
    publish_scanout(Some(narf_graphics_driver::generic::GenericFb::new(
        phys_base,
        w,
        h,
        stride_bytes,
        32,
    )));
    if aux_backlight {
        crate::intel_dpcd_bl::resume_for_bar(&display.gtt_mmadr).ok()?;
    }
    Some(scanout)
}

/// Register one exact-match PCI driver per row of the canonical
/// device table, plus the class-match backstop.
pub fn register_pci_driver() {
    for (name, device) in ids::pci_matches() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: INTEL_VENDOR,
                device,
            },
            probe,
        });
    }
    // Class-match backstop. The probe body filters non-Intel
    // vendors so AMD / NVIDIA / virtio-gpu cards aren't claimed,
    // and announces unknown Intel DIDs instead of failing silently.
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "intel-gpu-class",
        kind: narf_bus::MatchKind::Class {
            class: PCI_CLASS_DISPLAY,
            mask: 0xFF,
        },
        probe,
    });
}

// ── Framebuffer-console publication (lane 1, #1010 item 4) ──────
//
// Mirrors the AMD publication protocol in `amdgpu_dcn_display`:
// an ACTIVE slot plus a single observer fn pointer, so the fb
// crate (which depends on this crate, not the reverse) can
// follow the Intel scanout exactly the way it follows AMD's.
// Publishing records ACTIVE first; an observer installed late
// is told the current value immediately, so install order
// between probe (Stage::Device) and the fb initcall
// (Stage::Late) does not matter.

/// Told when the active Intel scanout appears or goes away.
pub type ScanoutObserver = fn(Option<narf_graphics_driver::generic::GenericFb>);
static ACTIVE_GENERIC: IrqSafeSpinLock<(u64, Option<narf_graphics_driver::generic::GenericFb>)> =
    IrqSafeSpinLock::new((0, None));
static SCANOUT_OBSERVER: IrqSafeSpinLock<Option<ScanoutObserver>> = IrqSafeSpinLock::new(None);

/// The Intel scanout currently published to the fb console.
pub fn active_scanout_generic() -> Option<narf_graphics_driver::generic::GenericFb> {
    ACTIVE_GENERIC.lock().1
}

/// Install the fb-console observer. Called once during
/// Stage::Late; a scanout that already exists is replayed
/// immediately so the edge cannot be missed.
pub fn register_scanout_observer(observer: ScanoutObserver) {
    *SCANOUT_OBSERVER.lock() = Some(observer);
    let current = ACTIVE_GENERIC.lock().1;
    if current.is_some() {
        observer(current);
    }
}

/// Publish (or withdraw) the Intel scanout. Locks are released
/// before the observer runs, so an observer that reads
/// `active_scanout_generic` cannot deadlock against this.
fn publish_scanout(scanout: Option<narf_graphics_driver::generic::GenericFb>) {
    publish_scanout_owned(scanout, 0);
}
fn publish_scanout_owned(scanout: Option<narf_graphics_driver::generic::GenericFb>, serial: u64) {
    *ACTIVE_GENERIC.lock() = (serial, scanout);
    let observer = *SCANOUT_OBSERVER.lock();
    if let Some(observer) = observer {
        observer(scanout);
    }
    // #1020: a scanout publish is a full-frame update, which is
    // what exits PSR — notify the eDP runtime. No-op when no
    // PSR session is active; called with no locks held, like
    // the observer above.
    if scanout.is_some() {
        crate::intel_gpu_edp::on_scanout_published();
    }
}

/// Reserve a nonzero identity for an external display publication.
///
/// Gen12 SST, the USB-C DP bridge and the Display-14 external route share one
/// namespace so a delayed detach can never mistake another route's image for
/// its own. Exhaustion is fail-closed instead of wrapping and reusing an
/// identity.
pub(crate) fn next_external_scanout_serial() -> Option<u64> {
    NEXT_DP_SESSION
        .fetch_update(
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
            |n| n.checked_add(1),
        )
        .ok()
}

/// Publish one successfully activated external scanout under its owner serial.
pub(crate) fn publish_external_scanout(
    scanout: narf_graphics_driver::generic::GenericFb,
    serial: u64,
) {
    debug_assert_ne!(serial, 0);
    publish_scanout_owned(Some(scanout), serial);
}

/// Withdraw an external image only while `serial` still owns the publication.
/// Returns whether the active image was withdrawn.
pub(crate) fn withdraw_external_scanout(serial: u64) -> bool {
    let withdrew = {
        let mut active = ACTIVE_GENERIC.lock();
        external_stop::withdraw(&mut active, serial)
    };
    if withdrew {
        let observer = *SCANOUT_OBSERVER.lock();
        if let Some(observer) = observer {
            observer(None);
        }
    }
    withdrew
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&IntelGpu) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Permanent probe-mapped display identity. Slow AUX/modeset operations use
/// this snapshot under a LegacyGuard rather than retaining CONTROLLER while
/// responsive waits run framebuffer pumps which also query the controller.
#[derive(Copy, Clone, Debug)]
pub(crate) struct DisplayInfo {
    pub gtt_mmadr: MmioRegion,
    pub chip: ChipInfo,
    /// `GMD_ID`, or `None` on pre-GMD generations (Gen11, Gen9).
    pub gmd_id: Option<u32>,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
}

impl DisplayInfo {
    /// A mode window over the snapshot's mapping, for slow AUX /
    /// modeset work that must not retain CONTROLLER (see the
    /// struct docs). `pub(crate)` so the VRR toggle path can run
    /// its DPCD write off the snapshot.
    pub(crate) fn mode_window(&self) -> ModeWindow {
        ModeWindow::new(self.gtt_mmadr, self.device, self.cap)
    }
    /// The display function's PCI (vendor, device).
    pub(crate) fn pci_id(&self) -> (u16, u16) {
        (self.device.id.vendor, self.device.id.device)
    }
}

/// Current PCI authority and D0 checked window for owned modesets. Slow
/// register programming never holds CONTROLLER or uses a prior grant alone.
#[derive(Debug)]
pub(crate) struct ModeWindow {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    io: crate::intel_gpu_gt_hw::AuthorizedWindow,
}
impl ModeWindow {
    fn new(bar: MmioRegion, device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Self {
        Self {
            device,
            cap,
            io: crate::intel_gpu_gt_hw::AuthorizedWindow::new(bar, cap),
        }
    }
    fn powered(&self) -> bool {
        narf_bus::pci::power_state(&self.cap, &self.device)
            == Ok(Some(narf_bus::pci::PciPowerState::D0))
    }
}
impl crate::intel_gpu_aux::MmioWindow for ModeWindow {
    fn gen12_display_family(&self) -> Option<crate::intel_gpu_gt::Gen12Platform> {
        match crate::intel_gpu_gt::GtPlatform::from_pci(
            self.device.id.vendor,
            self.device.id.device,
        ) {
            Some(crate::intel_gpu_gt::GtPlatform::Gen12(family)) => Some(family),
            _ => None,
        }
    }
    fn gen11_display_platform(&self) -> Option<crate::intel_gpu_gt::Gen11Platform> {
        match crate::intel_gpu_gt::GtPlatform::from_pci(
            self.device.id.vendor,
            self.device.id.device,
        ) {
            Some(crate::intel_gpu_gt::GtPlatform::Gen11(platform)) => Some(platform),
            _ => None,
        }
    }
    fn gen9_display_platform(
        &self,
    ) -> Option<(
        crate::intel_gpu_gt::Gen9Platform,
        crate::intel_gpu_gen9_ddi::SkuFamily,
    )> {
        match crate::intel_gpu_gt::GtPlatform::from_pci(
            self.device.id.vendor,
            self.device.id.device,
        ) {
            // Gen9 LP takes the Gen9 sessions with its own PHY, PLL and
            // hotplug bank; the SKU family selects nothing for it.
            Some(crate::intel_gpu_gt::GtPlatform::Gen9(platform)) => Some((
                platform,
                crate::intel_gpu_gen9_ddi::sku_family_for_did(self.device.id.device),
            )),
            _ => None,
        }
    }
    fn c20_hdmi_tx_cfg1(&self) -> Option<u16> {
        use crate::intel_gpu_gt::GtPlatform;
        use crate::intel_gpu_xelpg_hdmi::c20_hdmi_tx_cfg1;
        match GtPlatform::from_pci(self.device.id.vendor, self.device.id.device)? {
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake) => {
                // INTEL_MTL_U_IDS, or an Arrow Lake-S host bridge
                // (`is_arrowlake_s_by_host_bridge`).
                let mtl_u = matches!(self.device.id.device, 0x7D40 | 0x7D45);
                let arl_s = narf_bus::devices().iter().any(|d| {
                    d.id.vendor == 0x8086
                        && d.id.class >> 8 == 0x0600
                        && matches!(d.id.device, 0x7D1C | 0x7D2D | 0x7D2E | 0x7D2F)
                });
                Some(c20_hdmi_tx_cfg1(if mtl_u || arl_s { 3 } else { 7 }, 2))
            }
            _ => None,
        }
    }
    fn tgl_uy(&self) -> bool {
        crate::intel_gpu_gen12_combo_phy::is_tgl_uy(self.device.id.device)
    }
    fn gen12_hpd_profile(&self) -> Option<crate::intel_gpu_dp::HpdProfile> {
        use narf_bus::BusAddr;
        let BusAddr::Pcie(gpu) = self.device.addr else {
            return None;
        };
        let family = crate::intel_gpu_aux::SourceFamily::of(self)?;
        crate::intel_gpu_dp::HpdProfile::observed_for_source(
            family,
            gpu.segment,
            &narf_bus::devices(),
        )
    }
    fn display_access_ok(&self) -> bool {
        self.powered()
    }
    fn read32(&self, reg: u64) -> u32 {
        if self.powered() {
            self.io.read32(reg)
        } else {
            u32::MAX
        }
    }
    fn write32(&self, reg: u64, value: u32) {
        if self.powered() {
            self.io.write32(reg, value)
        }
    }
}
pub(crate) fn with_display_info<R>(f: impl FnOnce(&DisplayInfo) -> R) -> Option<R> {
    let display = CONTROLLER.lock().as_ref().map(|gpu| DisplayInfo {
        gtt_mmadr: gpu.gtt_mmadr,
        chip: gpu.chip,
        gmd_id: gpu.gmd_id,
        device: gpu.display_device,
        cap: gpu.display_cap,
    })?;
    Some(f(&display))
}

// ── External DisplayPort session (lane Q4, #1092) ──────────────
//
// The HPD-driven external-DP path: `intel_gpu_dp` owns the
// session logic (caps, negotiation, training, ELD publication);
// this glue owns the parts that need the probed controller —
// the BAR window, the scanout allocation (same allocator and
// lifetime as probe's own scanout: the GTT allocator has no
// free path, so the bounded route/allocation remains retained
// after stop or partial loss), and serial-specific scanout publication
// through the same ACTIVE + observer protocol as the takeover
// path. Since #1017 a session claims its pipe from
// `intel_gpu_multipipe` and allocates in that pipe's GGTT
// window, so an internal panel and external sessions scan out
// concurrently; the fb-console publication slot is still
// single, so the last HPD event wins it.

/// Retained route/allocation; failed stop never drops or replaces its graph.
type DpSessionState = external_stop::Session<ScanoutAllocation>;
static NEXT_DP_SESSION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

static DP_SESSION: IrqSafeSpinLock<Option<DpSessionState>> = IrqSafeSpinLock::new(None);

/// Live external-HDMI session state; same shape and
/// discipline as [`DpSessionState`]. A connector is either
/// DP or HDMI at a time — whichever probe answers owns the
/// DDI's session slot.
struct HdmiSessionState {
    bar: u64,
    conn: crate::intel_gpu_hdmi::HdmiConnection,
    fb: crate::intel_gpu_modeset::Framebuffer,
    alloc: ScanoutAllocation,
    /// The publication serial: an HDMI unplug withdraws only its own image.
    serial: u64,
}

static HDMI_SESSION: IrqSafeSpinLock<Option<HdmiSessionState>> = IrqSafeSpinLock::new(None);

/// Rocket Lake's owned panel route needs the VBT to declare eDP on port A
/// (`intel_ddi_init` creates the eDP connector only then); without one the
/// panel stays on the firmware route, with a log line.
fn rkl_panel_declared() -> bool {
    let declared = crate::intel_gpu_vbt::gen12_ddc_overrides()
        .edp_on_a_for(crate::intel_gpu_gt::Gen12Platform::RocketLake);
    if !declared {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "intel-gpu: Rocket Lake panel refused: the VBT declares no eDP on port A"
        );
    }
    declared
}

/// Drain pending combo-DDI hotplug events and act on them.
/// Called once at the end of probe (a sink already attached at
/// boot is picked up there); a future periodic-polled caller
/// can invoke it the same way.
pub fn poll_dp_hpd_events() {
    // The inherited pipe, port and shared watermarks have no native
    // allocation. A hotplug modeset must not overwrite their configuration.
    let Some(bar) =
        with_controller(|gpu| (!gpu.firmware_display).then_some(gpu.gtt_mmadr)).flatten()
    else {
        return;
    };
    // Gen9: the whole external-output pass (hotplug, probe, connect,
    // disconnect) runs with DC states exited; if they cannot be, nothing
    // runs. Inert on every other display.
    let Ok(_dc) = crate::intel_gpu_gen9_dc_states::acquire_for_bar(
        &bar,
        crate::intel_gpu_gen9_dc_states::Gen9DcUser::External,
    ) else {
        return;
    };
    let display = crate::intel_gpu_kms::display_for_bar(&bar);
    let mut ownership = match display.as_ref() {
        Some(display) => match display.legacy() {
            Ok(guard) => Some(guard),
            Err(_) => return,
        },
        None => None,
    };
    // Meteor Lake external outputs drain first; the Gen12 loop below never
    // reports an event on that generation, and this drain never runs on Gen12.
    // The held legacy guard admits no KMS presenter, cursor or color, so FBC
    // and PSR are off and nothing needs bracketing; the panel's KMS owner is
    // not suspended either, since its display-14 proofs hold beside a lit
    // Pipe B-D (they re-prove the layout on every use).
    for _ in 0..MTL_EVENTS_PER_DRAIN {
        if !service_mtl_display(&mut || {}, &mut || {}) {
            break;
        }
    }
    loop {
        let event = with_display_info(|gpu| {
            let window = gpu.mode_window();
            poll_external_hpd(&window, gpu.chip.generation)
        });
        match event {
            Some(Some(event)) => {
                if let Some(guard) = ownership.as_mut() {
                    // External programming may change pipe ownership or
                    // shared watermarks. Re-admit fixed internal flips only
                    // after an explicit owned-console re-establishment.
                    guard.suspend();
                }
                handle_dp_hpd_event(event);
            }
            _ => return,
        }
    }
}

fn enable_external_hpd<M: crate::intel_gpu_aux::MmioWindow>(mmio: &M, generation: Generation) {
    if generation.external_display_supported()
        && crate::intel_gpu_aux::SourceFamily::of(mmio).is_some()
    {
        crate::intel_gpu_dp::enable_hpd_interrupts(mmio);
    }
}

fn poll_external_hpd<M: crate::intel_gpu_aux::MmioWindow>(
    mmio: &M,
    generation: Generation,
) -> Option<crate::intel_gpu_dp::HpdEvent> {
    if !generation.external_display_supported()
        || crate::intel_gpu_aux::SourceFamily::of(mmio).is_none()
    {
        return None;
    }
    crate::intel_gpu_dp::poll_hpd_event(mmio)
}

/// The AUX / DDI IO well requests this driver holds for each Gen12 combo
/// port with a sink attached, indexed by DDI.
static PORT_WELLS: IrqSafeSpinLock<[crate::intel_gpu_dp::PortWells; 9]> =
    IrqSafeSpinLock::new([crate::intel_gpu_dp::PortWells { aux: 0, ddi: 0 }; 9]);

/// Power the connected port's DDI IO and AUX wells before any session
/// talks to the sink (Gen12 combo ports; a no-op elsewhere).
fn hold_port_wells(ddi: crate::intel_gpu_ddi::Ddi) {
    let got = with_display_info(|gpu| {
        let window = gpu.mode_window();
        crate::intel_gpu_aux::SourceFamily::of(&window)
            .and_then(|family| family.gen12())
            .map(|family| crate::intel_gpu_dp::request_port_wells(&window, family, ddi))
    })
    .flatten()
    .unwrap_or_default();
    let mut held = PORT_WELLS.lock();
    let slot = &mut held[ddi as usize];
    slot.aux |= got.aux;
    slot.ddi |= got.ddi;
}

/// Drop the well requests [`hold_port_wells`] raised for `ddi` once its
/// sink is gone and its session is down.
fn drop_port_wells(ddi: crate::intel_gpu_ddi::Ddi) {
    let held = core::mem::take(&mut PORT_WELLS.lock()[ddi as usize]);
    if held == crate::intel_gpu_dp::PortWells::default() {
        return;
    }
    let _ = with_display_info(|gpu| {
        crate::intel_gpu_dp::release_port_wells(&gpu.mode_window(), held);
    });
}

fn handle_dp_hpd_event(event: crate::intel_gpu_dp::HpdEvent) {
    use crate::intel_gpu_dp::HpdEvent;
    match event {
        HpdEvent::Connected(ddi) => {
            // Sessions admit per connector: a sink on another DDI gets its
            // own route on its own pipe beside the ones already live.
            if external_session_owns(ddi) {
                return;
            }
            hold_port_wells(ddi);
            // An MST branch device (hub / dock / daisy-chain
            // monitor) gets the MST session (#1017): if the
            // device advertises MST and a stream comes up, the
            // SST path never runs for this connector. Anything
            // else — an SST sink, or an MST attempt that found
            // no usable sink — falls through to the SST connect.
            if mst_session_ddi() == Some(ddi) {
                // MST session already live on this connector; a
                // repeat connect event changes nothing.
                return;
            }
            if mst_connect(ddi) {
                let stored = {
                    let session = MST_SESSION.lock();
                    session.as_ref().and_then(|s| {
                        s.streams
                            .first()
                            .map(|g| (g.alloc, g.fb, g.mode.h_active, g.mode.v_active))
                    })
                };
                if let Some((alloc, fb, width, height)) = stored {
                    publish_scanout(Some(narf_graphics_driver::generic::GenericFb::new(
                        alloc.phys_base,
                        width as u32,
                        height as u32,
                        fb.stride_bytes,
                        32,
                    )));
                }
                return;
            }
            if let Some(conn) = dp_connect(ddi) {
                // Publish from the stored session state (the
                // retained allocation + framebuffer the session
                // actually scans out).
                let stored = {
                    let session = DP_SESSION.lock();
                    session.as_ref().map(|s| (s.alloc, s.fb, s.serial))
                };
                if let Some((alloc, fb, serial)) = stored {
                    publish_external_scanout(
                        narf_graphics_driver::generic::GenericFb::new(
                            alloc.phys_base,
                            conn.mode.h_active as u32,
                            conn.mode.v_active as u32,
                            fb.stride_bytes,
                            32,
                        ),
                        serial,
                    );
                }
            } else if let Some(conn) = hdmi_connect(ddi) {
                // The DP probe did not answer; the HDMI one
                // did. Publish from the HDMI session state the
                // same way.
                let stored = {
                    let session = HDMI_SESSION.lock();
                    session.as_ref().map(|s| (s.alloc, s.fb, s.serial))
                };
                if let Some((alloc, fb, serial)) = stored {
                    publish_external_scanout(
                        narf_graphics_driver::generic::GenericFb::new(
                            alloc.phys_base,
                            conn.mode.h_active as u32,
                            conn.mode.v_active as u32,
                            fb.stride_bytes,
                            32,
                        ),
                        serial,
                    );
                }
            }
        }
        HpdEvent::Disconnected(ddi) => {
            disconnect_sessions(ddi);
            // A stop that was not proven keeps its session, and with it the
            // port's wells.
            if !external_session_owns(ddi) {
                drop_port_wells(ddi);
            }
        }
        HpdEvent::RetrainRequired(ddi) => {
            hdcp_short_pulse(ddi);
            if mst_session_ddi() == Some(ddi) {
                // MST links don't revalidate per-lane status the
                // SST way; branch notifications are the change
                // channel. Drain them (they're also how a sink
                // disappearing mid-session first surfaces).
                mst_poll_notifications(ddi);
            }
            // A retrain may change timing/resources. Preserve the already-owned
            // graph; the bounded next17 owner only retires an explicit loss.
            // Fresh retrain/activation remains a separate resource transaction.
        }
    }
}

/// HDCP's share of a DP short pulse on `ddi`: the live SST session's
/// (`intel_dp_short_pulse`) or the MST session's (`intel_dp_mst_hpd_irq`)
/// CP_IRQ goes to `intel_hdcp_handle_cp_irq`. Inert without
/// `narf.intel.hdcp=1`.
fn hdcp_short_pulse(ddi: crate::intel_gpu_ddi::Ddi) {
    let sst = DP_SESSION
        .lock()
        .as_ref()
        .is_some_and(|state| state.conn.ddi == ddi && state.live());
    let mst = !sst && mst_session_ddi() == Some(ddi);
    if !sst && !mst {
        return;
    }
    with_display_info(|gpu| {
        let window = gpu.mode_window();
        let mut aux = crate::intel_gpu_aux::IntelAux::new(&window, ddi);
        crate::intel_hdcp_live::short_pulse(&mut aux, crate::intel_hdcp_live::gen12_key(ddi), mst);
    });
}

/// Tear down whichever session owns `ddi` after its sink went away.
fn disconnect_sessions(ddi: crate::intel_gpu_ddi::Ddi) {
    // HDCP off before the port goes down (`intel_hdcp_disable`).
    with_display_info(|gpu| crate::intel_hdcp_live::route_stopping_gen12(&gpu.mode_window(), ddi));
    if mst_session_ddi() == Some(ddi) {
        if mst_disconnect(ddi) {
            publish_scanout(None);
        }
        return;
    }
    let owns = DP_SESSION
        .lock()
        .as_ref()
        .is_some_and(|state| state.conn.ddi == ddi);
    if owns {
        let bar = with_display_info(|gpu| gpu.gtt_mmadr);
        if let Some(bar) = bar {
            let _ = step_external_sst_inner(&bar, true);
        }
        return;
    }
    let session = HDMI_SESSION.lock().take();
    if let Some(state) = session {
        if state.conn.ddi == ddi {
            let stopped = with_display_info(|gpu| {
                let window = gpu.mode_window();
                let stopped = crate::intel_gpu_hdmi::disconnect(&window, &state.conn);
                if stopped {
                    // The pipe is proven stopped: give it back and
                    // repartition the DBUF over the pipes still lit.
                    crate::intel_gpu_multipipe::release_pipe(state.conn.pipe, ddi);
                    crate::intel_gpu_multipipe::reprogram_active_dbuf_shares(&window);
                }
                stopped
            })
            .unwrap_or(false);
            if stopped {
                withdraw_external_scanout(state.serial);
            } else {
                *HDMI_SESSION.lock() = Some(state);
            }
        } else {
            *HDMI_SESSION.lock() = Some(state);
        }
    }
}

/// Run one external-DP connect against the probed controller:
/// probe the sink over AUX, claim a pipe, allocate its scanout
/// in the pipe's GGTT window, activate on that pipe. On
/// success or partial activation the complete route/allocation is retained.
/// A second activation cannot replace a live, stopped or quarantined graph.
/// Native pipe/surface witnesses precede scanout publication.
fn dp_connect(ddi: crate::intel_gpu_ddi::Ddi) -> Option<crate::intel_gpu_dp::DpConnection> {
    if DP_SESSION.lock().is_some() {
        return None;
    }
    let serial = next_external_scanout_serial()?;
    with_display_info(|gpu| {
        if !gpu.chip.generation.external_display_supported() {
            return None;
        }
        let window = gpu.mode_window();
        let family = crate::intel_gpu_aux::SourceFamily::of(&window)?;
        let probe = crate::intel_gpu_dp::probe_sink(&window, ddi).ok()?;
        let pipe =
            crate::intel_gpu_multipipe::claim_pipe_for(crate::intel_gpu_multipipe::PipeOwner {
                ddi,
                used_for: crate::intel_gpu_multipipe::PipeUse::ExternalSst,
            })?;
        // When this claim lights a second (or third) pipe, the
        // session modesets with its DBUF share and the pipes
        // already live are reprogrammed to theirs afterwards.
        let share = {
            let active = crate::intel_gpu_multipipe::active_pipes();
            if active.len() >= 2 {
                crate::intel_gpu_multipipe::share_for(&window, &active, pipe)
            } else {
                None
            }
        };
        let width = probe.mode.h_active as u32;
        let height = probe.mode.v_active as u32;
        let stride_bytes = padded_stride_bytes(width);
        let size_bytes = scanout_size_bytes(width, height);
        let alloc = match crate::intel_gpu_gtt::alloc_contiguous_scanout_at(
            &gpu.gtt_mmadr,
            crate::intel_gpu_multipipe::scanout_gtt_offset(pipe),
            size_bytes,
        ) {
            Ok(alloc) => alloc,
            Err(_) => {
                crate::intel_gpu_multipipe::release_pipe(pipe, ddi);
                return None;
            }
        };
        let alloc = ScanoutAllocation {
            gtt_offset: alloc.gtt_offset,
            phys_base: alloc.phys_base(),
            order: alloc.order,
            size_bytes: alloc.size_bytes,
        };
        let fb = crate::intel_gpu_modeset::Framebuffer {
            phys_addr: alloc.gtt_offset as u64,
            stride_bytes,
            format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
        };
        let activated = crate::intel_gpu_dp::activate_on_pipe(&window, &probe, &fb, pipe, share);
        let (conn, success) = match activated {
            Ok(conn) => (conn, true),
            Err(_) => (
                crate::intel_gpu_dp::DpConnection {
                    family,
                    ddi,
                    pipe,
                    mode: probe.mode,
                    trained: crate::dp_link_training::TrainedLink {
                        rate: probe.negotiated.rate,
                        lanes: probe.negotiated.lanes,
                        vswing_pe: Default::default(),
                    },
                    caps: probe.caps,
                    audio_published: false,
                    pcon: crate::dp_pcon::PconLink::Untouched,
                },
                false,
            ),
        };
        // Once allocation/programming may have happened, failure retains the
        // exact claimed route and BO. Never release based on best-effort rollback.
        if success {
            crate::intel_gpu_multipipe::reprogram_active_dbuf_shares(&window);
        }
        let mut state = DpSessionState::adopt(
            &window,
            conn.clone(),
            fb,
            alloc,
            serial,
            gpu.gtt_mmadr.phys.raw(),
        );
        if !success {
            state.quarantine();
        }
        let qualified = state.live();
        *DP_SESSION.lock() = Some(state);
        qualified.then_some(conn)
    })
    .flatten()
}

/// HDMI twin of [`dp_connect`]: DDC probe over GMBUS,
/// scanout allocation, HDMI activate (SCDC where the rate
/// demands it, WRPLL modeset, AVI DIP, ELD publication).
/// The HPD handler tries this only after the DP probe did
/// not answer — an HDMI sink never answers AUX.
fn hdmi_connect(ddi: crate::intel_gpu_ddi::Ddi) -> Option<crate::intel_gpu_hdmi::HdmiConnection> {
    if HDMI_SESSION.lock().is_some() {
        return None;
    }
    let serial = next_external_scanout_serial()?;
    with_display_info(|gpu| {
        if !gpu.chip.generation.external_display_supported() {
            return None;
        }
        let window = gpu.mode_window();
        crate::intel_gpu_aux::SourceFamily::of(&window)?;
        let ddc = crate::intel_gpu_vbt::gen12_ddc_overrides();
        let probe = crate::intel_gpu_hdmi::probe_sink(&window, ddi, &ddc).ok()?;
        // The HDMI route claims its own pipe beside the panel and any other
        // external, as the DP route does; a second (or third) lit pipe takes
        // its DBUF share and the live pipes are reprogrammed to theirs.
        let pipe =
            crate::intel_gpu_multipipe::claim_pipe_for(crate::intel_gpu_multipipe::PipeOwner {
                ddi,
                used_for: crate::intel_gpu_multipipe::PipeUse::ExternalHdmi,
            })?;
        let share = {
            let active = crate::intel_gpu_multipipe::active_pipes();
            if active.len() >= 2 {
                crate::intel_gpu_multipipe::share_for(&window, &active, pipe)
            } else {
                None
            }
        };
        let width = probe.mode.h_active as u32;
        let height = probe.mode.v_active as u32;
        let stride_bytes = padded_stride_bytes(width);
        let size_bytes = scanout_size_bytes(width, height);
        let Ok(alloc) = crate::intel_gpu_gtt::alloc_contiguous_scanout_at(
            &gpu.gtt_mmadr,
            crate::intel_gpu_multipipe::scanout_gtt_offset(pipe),
            size_bytes,
        ) else {
            crate::intel_gpu_multipipe::release_pipe(pipe, ddi);
            return None;
        };
        let fb = crate::intel_gpu_modeset::Framebuffer {
            phys_addr: alloc.gtt_offset as u64,
            stride_bytes,
            format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
        };
        match crate::intel_gpu_hdmi::activate_on_pipe(&window, &probe, &fb, pipe, share) {
            Ok(conn) => {
                crate::intel_gpu_multipipe::reprogram_active_dbuf_shares(&window);
                *HDMI_SESSION.lock() = Some(HdmiSessionState {
                    bar: gpu.gtt_mmadr.phys.raw(),
                    conn: conn.clone(),
                    serial,
                    fb,
                    alloc: ScanoutAllocation {
                        gtt_offset: alloc.gtt_offset,
                        phys_base: alloc.phys_base(),
                        order: alloc.order,
                        size_bytes: alloc.size_bytes,
                    },
                });
                Some(conn)
            }
            Err(_) => {
                // A failed activation may have programmed part of the pipe.
                // Only a proven local stop gives the pipe and its backing
                // back; otherwise both stay claimed.
                let mut modeset = crate::intel_gpu_modeset::Modeset::for_pipe(&window, ddi, pipe);
                if let Some(family) = crate::intel_gpu_aux::SourceFamily::of(&window) {
                    modeset.set_source_family(family);
                }
                if modeset.try_teardown().is_ok() {
                    crate::intel_gpu_multipipe::release_pipe(pipe, ddi);
                    crate::intel_gpu_gtt::free_contiguous_scanout(&alloc);
                }
                None
            }
        }
    })
    .flatten()
}

/// The DDI some external session (DP SST, HDMI or MST) already owns.
fn external_session_owns(ddi: crate::intel_gpu_ddi::Ddi) -> bool {
    DP_SESSION
        .lock()
        .as_ref()
        .is_some_and(|state| state.conn.ddi == ddi)
        || HDMI_SESSION
            .lock()
            .as_ref()
            .is_some_and(|state| state.conn.ddi == ddi)
        || mst_session_ddi() == Some(ddi)
}

/// One current-authority bounded local step. No wait or GT mutex is held.
fn step_external_sst_inner(bar: &MmioRegion, stop: bool) -> Result<bool, narf_filesystem::FsError> {
    use crate::intel_gpu_aux::MmioWindow;
    use narf_filesystem::FsError;
    if DP_SESSION
        .lock()
        .as_ref()
        .is_none_or(|state| state.bar != bar.phys.raw())
    {
        return Ok(true);
    }
    let Some(info) = with_display_info(|gpu| *gpu).filter(|gpu| gpu.gtt_mmadr.phys == bar.phys)
    else {
        return Err(FsError::NoDevice);
    };
    let io = info.mode_window();
    let sink = {
        let mut slot = DP_SESSION.lock();
        if let Some(state) = slot.as_mut().filter(|state| stop && state.running()) {
            if crate::intel_gpu_multipipe::pipe_owner(state.conn.pipe)
                != Some(crate::intel_gpu_multipipe::PipeOwner {
                    ddi: state.conn.ddi,
                    used_for: crate::intel_gpu_multipipe::PipeUse::ExternalSst,
                })
            {
                state.quarantine();
                return Err(FsError::NoDevice);
            }
            state.preflight(&io)?;
            state.request_stop();
            Some((state.serial, state.conn.ddi, state.conn.caps.dpcd_rev))
        } else {
            None
        }
    };
    if let Some((_serial, ddi, revision)) = sink {
        if revision >= 0x11 {
            use crate::dp_aux::AuxChannel;
            let mut aux = crate::intel_gpu_aux::IntelAux::new(&io, ddi);
            // An unplugged sink may NACK. Local fetch/port witnesses remain
            // mandatory; no wait or caller cancellation releases the graph.
            let _ = aux.dpcd_write(0x600, &[2]);
        }
    }
    let mut slot = DP_SESSION.lock();
    let Some(state) = slot.as_mut().filter(|state| state.bar == bar.phys.raw()) else {
        return Ok(true);
    };
    if !io.display_access_ok() {
        state.quarantine();
        return Err(FsError::NoDevice);
    }
    if stop {
        state.request_stop();
    }
    if !state.stopped() {
        if crate::intel_gpu_multipipe::pipe_owner(state.conn.pipe)
            != Some(crate::intel_gpu_multipipe::PipeOwner {
                ddi: state.conn.ddi,
                used_for: crate::intel_gpu_multipipe::PipeUse::ExternalSst,
            })
        {
            state.quarantine();
            return Err(FsError::NoDevice);
        }
        if !state.running() && state.conn.audio_published {
            crate::intel_gpu_audio::audio_codec_disable(&io, state.conn.pipe.transcoder());
            narf_drivers_sound::display_audio::clear_display_audio(
                crate::intel_gpu_dp::sink_id_for(state.conn.ddi),
            );
            state.conn.audio_published = false;
        }
    }
    let was_live = state.live();
    let done = state.step(&io, narf_time::monotonic_ns())?;
    let serial = state.serial;
    let publish = (!was_live && state.live()).then(|| {
        narf_graphics_driver::generic::GenericFb::new(
            state.alloc.phys_base,
            u32::from(state.conn.mode.h_active),
            u32::from(state.conn.mode.v_active),
            state.fb.stride_bytes,
            32,
        )
    });
    drop(slot);
    if let Some(fb) = publish {
        publish_external_scanout(fb, serial);
    }
    if done {
        withdraw_external_scanout(serial);
    }
    Ok(done)
}
fn step_external_sst(bar: &MmioRegion, stop: bool) -> Result<bool, narf_filesystem::FsError> {
    // Preserve idle/older-platform recovery: an absent external owner must
    // not set KMS.blocked when Device::recover legitimately has no work.
    if legacy_external_routes_stopped(bar) {
        return Ok(true);
    }
    let display = crate::intel_gpu_kms::display_for_bar(bar);
    let _guard = match display.as_ref() {
        Some(display) => Some(display.legacy_drain()?),
        None => None,
    };
    // Existing HDMI/MST owners have no incremental, cancellable idle proof.
    if unsupported_external_for_bar(bar) {
        return Err(narf_filesystem::FsError::Busy);
    }
    step_external_sst_inner(bar, stop)
}
/// Existing runtime actor calls this outside the GT mutex. No executor bridge.
pub(crate) fn service_external_sst(bar: &MmioRegion) {
    // HDCP (`narf.intel.hdcp=1`; inert otherwise) on the routes as they
    // stand before this pass's hotplug work.
    crate::intel_hdcp_live::service(bar);
    service_mtl_external_for_bar(bar);
    let active = DP_SESSION
        .lock()
        .as_ref()
        .is_some_and(|state| state.bar == bar.phys.raw() && !state.stopped());
    if !active {
        return;
    }
    let display = crate::intel_gpu_kms::display_for_bar(bar);
    let _guard = match display.as_ref() {
        Some(display) => match display.legacy_drain() {
            Ok(g) => Some(g),
            Err(_) => return,
        },
        None => None,
    };
    let event = with_display_info(|gpu| {
        let io = gpu.mode_window();
        poll_external_hpd(&io, gpu.chip.generation)
    })
    .flatten();
    if let Some(crate::intel_gpu_dp::HpdEvent::RetrainRequired(ddi)) = event {
        hdcp_short_pulse(ddi);
    }
    let stop = DP_SESSION.lock().as_ref().is_some_and(|state| {
        event == Some(crate::intel_gpu_dp::HpdEvent::Disconnected(state.conn.ddi))
    });
    if let (true, Some(crate::intel_gpu_dp::HpdEvent::Disconnected(ddi))) = (stop, event) {
        // HDCP off before the port goes down (`intel_hdcp_disable`).
        with_display_info(|gpu| {
            crate::intel_hdcp_live::route_stopping_gen12(&gpu.mode_window(), ddi)
        });
    }
    if crate::intel_gpu_dp::hpd_uncertain() {
        if let Some(state) = DP_SESSION.lock().as_mut() {
            state.quarantine();
        }
    }
    let _ = step_external_sst_inner(bar, stop);
}
/// HDCP (`crate::intel_hdcp_live`): the live Gen12 SST sessions on `bar` as
/// (DDI, CPU transcoder index, DDC pin for an HDMI session). MST is not
/// listed.
pub(crate) fn hdcp_gen12_sessions(
    bar: &MmioRegion,
) -> alloc::vec::Vec<(
    crate::intel_gpu_ddi::Ddi,
    u8,
    Option<crate::intel_gpu_gmbus::PinPair>,
)> {
    let mut out = alloc::vec::Vec::new();
    if let Some(state) = DP_SESSION.lock().as_ref() {
        if state.bar == bar.phys.raw() && state.live() {
            out.push((state.conn.ddi, state.conn.pipe.transcoder() as u8, None));
        }
    }
    if let Some(state) = HDMI_SESSION.lock().as_ref() {
        if state.bar == bar.phys.raw() {
            out.push((
                state.conn.ddi,
                state.conn.pipe.transcoder() as u8,
                Some(state.conn.pin),
            ));
        }
    }
    out
}

/// HDCP (`crate::intel_hdcp_live`): the live Gen12 MST session on `bar` as
/// its DDI and streams (CPU transcoder index, VCPI), the master's first.
pub(crate) fn hdcp_gen12_mst(
    bar: &MmioRegion,
) -> Option<(crate::intel_gpu_ddi::Ddi, alloc::vec::Vec<(u8, u8)>)> {
    let session = MST_SESSION.lock();
    let state = session.as_ref().filter(|s| s.bar == bar.phys.raw())?;
    let streams: alloc::vec::Vec<(u8, u8)> = state
        .link
        .streams()
        .iter()
        .map(|s| (s.pipe.transcoder() as u8, s.vcpi))
        .collect();
    (!streams.is_empty()).then(|| (state.link.ddi(), streams))
}

/// No stop is inferred for unsupported HDMI/MST. Stopped SST leases remain
/// permanently reserved; this is an admission fact, never permission to reuse.
fn unsupported_external_for_bar(bar: &MmioRegion) -> bool {
    HDMI_SESSION
        .lock()
        .as_ref()
        .is_some_and(|state| state.bar == bar.phys.raw())
        || MST_SESSION
            .lock()
            .as_ref()
            .is_some_and(|state| state.bar == bar.phys.raw())
}
pub(crate) fn external_routes_stopped(bar: &MmioRegion) -> bool {
    legacy_external_routes_stopped(bar) && crate::intel_gpu_xelpg_external::routes_stopped()
}
// The MTL-family route has its own panel-serialized retirement. A live route
// there must not close KMS admission through the unrelated legacy SST drain.
fn legacy_external_routes_stopped(bar: &MmioRegion) -> bool {
    if !crate::intel_gpu_dp_bridge::sessions_stopped(bar.phys.raw()) {
        return false;
    }
    !unsupported_external_for_bar(bar)
        && DP_SESSION
            .lock()
            .as_ref()
            .is_none_or(|state| state.bar != bar.phys.raw() || state.stopped())
}

// ── Meteor Lake external SST (`intel_gpu_xelpg_external`) ───────
//
// The display-14 counterpart of the Gen12 glue above. The route itself —
// Type-C ownership, hotplug, link, local stop — is owned by
// `intel_gpu_xelpg_external`; this glue owns its scanout allocation and
// the serial-matched publication. The GTT allocator has no free path, so
// one allocation is retained per BAR and reused whenever the next mode
// fits; it lives in the pipe-B console GGTT window so it can never remap
// the internal panel's pipe-A window. Every other concurrently lit surface
// (MST streams, a second route) takes its own window
// (`mtl_scanout_window`), never a shared one. Gen12 never reaches this glue: every
// entry returns before register access unless the probed generation is
// Meteor Lake.

/// Retained MTL external scanout allocation: (BAR physical base, allocation).
static MTL_SCANOUT: IrqSafeSpinLock<Option<(u64, ScanoutAllocation)>> = IrqSafeSpinLock::new(None);
// MST secondary surfaces have separate GGTT and physical backing. The
// boot-console publication remains the first stream, as with SST.
static MTL_EXTRA_SCANOUTS: IrqSafeSpinLock<alloc::vec::Vec<(u64, u8, ScanoutAllocation)>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());
/// Serial of the published MTL external image (0 = none published).
static MTL_PUBLISHED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Serial of the second concurrent route's image (`narf.intel.ext_routes=2`,
/// route slot 1; 0 = none published).
static MTL_PUBLISHED_SECOND: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The image and pipe each route slot last published, so the sibling's
/// image takes the console back when the active one is withdrawn.
static MTL_SLOT_IMAGES: IrqSafeSpinLock<
    [Option<(
        narf_graphics_driver::generic::GenericFb,
        crate::intel_gpu_pipes::Pipe,
    )>; 2],
> = IrqSafeSpinLock::new([None, None]);
/// `MTL_EXTRA_SCANOUTS` key of the second route's surface (slot 1 never
/// carries MST streams, which take keys 1..).
const MTL_SECOND_SCANOUT_KEY: u8 = 0x80;

/// The console GGTT window (`scanout_gtt_offset`) of stream `stream` of the
/// route in slot `slot`. Every surface lit at the same time needs its own
/// window: an allocation at a window's offset rewrites that window's PTEs,
/// so two surfaces in one window would scan out the last one's pages. Slot
/// 0's streams (one SST/HDMI route, or up to three MST streams) take Pipe
/// B, C and D's windows in order; slot 1 (a second concurrent route, never
/// beside MST) takes Pipe C's. `None` past the last window.
fn mtl_scanout_window(slot: usize, stream: u8) -> Option<crate::intel_gpu_pipes::Pipe> {
    use crate::intel_gpu_pipes::Pipe;
    match (slot, stream) {
        (0, 0) => Some(Pipe::B),
        (0, 1) => Some(Pipe::C),
        (0, 2) => Some(Pipe::D),
        (1, 0) => Some(Pipe::C),
        _ => None,
    }
}

/// The publication serial of route slot `slot`.
fn mtl_slot_serial(slot: usize) -> &'static core::sync::atomic::AtomicU64 {
    if slot == 0 {
        &MTL_PUBLISHED
    } else {
        &MTL_PUBLISHED_SECOND
    }
}
/// The pipe (CRTC) scanning out the published MTL external image, as
/// `pipe + 1` (0 = none published).
static MTL_PUBLISHED_PIPE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
/// Upper bound on hotplug events one probe-time drain acts on.
const MTL_EVENTS_PER_DRAIN: usize = 8;

/// The pipe (CRTC) scanning out the active Intel publication when it is
/// the MTL external route's image ([`active_scanout_generic`]); `None` for
/// the internal console or when nothing external is published.
pub fn active_external_pipe() -> Option<crate::intel_gpu_pipes::Pipe> {
    let serial = ACTIVE_GENERIC.lock().0;
    if serial == 0
        || (serial != MTL_PUBLISHED.load(core::sync::atomic::Ordering::Acquire)
            && serial != MTL_PUBLISHED_SECOND.load(core::sync::atomic::Ordering::Acquire))
    {
        return None;
    }
    let pipe = MTL_PUBLISHED_PIPE
        .load(core::sync::atomic::Ordering::Acquire)
        .checked_sub(1)?;
    crate::intel_gpu_pipes::Pipe::try_from(pipe).ok()
}

/// Publication requests one MTL pass makes of its caller.
#[derive(Copy, Clone, Debug)]
enum MtlPublication {
    /// Publish this image under this serial; it scans out on this pipe.
    Publish(
        narf_graphics_driver::generic::GenericFb,
        u64,
        crate::intel_gpu_pipes::Pipe,
    ),
    /// Withdraw the image published under this serial (only if current).
    Withdraw(u64),
}

/// The console GGTT window (`scanout_gtt_offset`) of stream `stream` of the
/// route in slot `slot`. Every surface lit at the same time needs its own
/// window: an allocation at a window's offset rewrites that window's PTEs,
/// so two surfaces in one window would scan out the last one's pages. Slot
/// 0's streams (one SST/HDMI route, or up to three MST streams) take Pipe
/// B, C and D's windows in order; slot 1 (a second concurrent route, never
/// beside MST) takes Pipe C's. `None` past the last window.
fn mtl_scanout_window(slot: usize, stream: u8) -> Option<crate::intel_gpu_pipes::Pipe> {
    use crate::intel_gpu_pipes::Pipe;
    match (slot, stream) {
        (0, 0) => Some(Pipe::B),
        (0, 1) => Some(Pipe::C),
        (0, 2) => Some(Pipe::D),
        (1, 0) => Some(Pipe::C),
        _ => None,
    }
}

/// One MTL external hotplug pass: poll the owned hotplug source; when an
/// event arrives run `before_event` (the panel's KMS pre-update: FBC and
/// PSR leave Pipe A before it may be repartitioned), let the route owner
/// act on it next to `display` with a retained-or-new scanout allocation,
/// run `after_event` (the panel's KMS post-update), then publish an
/// activated image (with the pipe it scans out on) or withdraw the image of
/// a route that is no longer live. Returns whether an event was handled.
// The hooks and sinks are the pass's whole caller contract; grouping them
// would only rename the parameters.
#[allow(clippy::too_many_arguments)]
fn mtl_external_pass_profile<M: crate::intel_gpu_aux::MmioWindow + ?Sized>(
    io: &M,
    profile: crate::intel_gpu_xelpg_external::ExternalDisplayProfile,
    bar: u64,
    display: &crate::intel_gpu_xelpg_external::MtlDisplay,
    before_event: &mut dyn FnMut(),
    after_event: &mut dyn FnMut(),
    alloc: &mut dyn FnMut(crate::intel_gpu_pipes::Pipe, u64) -> Option<ScanoutAllocation>,
    publication: &mut dyn FnMut(MtlPublication),
) -> bool {
    use crate::intel_gpu_xelpg_external::ServiceOutcome;
    let Some(event) = crate::intel_gpu_xelpg_external::poll_mtl_event_for_profile(io, profile)
    else {
        return false;
    };
    before_event();
    // The route slot this event lights (or relights) a route in: slot 1 is
    // a second concurrent route (`narf.intel.ext_routes=2`) with its own
    // retained surface in its own GGTT window.
    let slot = crate::intel_gpu_xelpg_external::event_slot(event.pin.port());
    let mut next_scanout = if slot == 0 { 0u8 } else { MTL_SECOND_SCANOUT_KEY };
    let mut stream = 0u8;
    let mut alloc_fb = |mode: &crate::intel_gpu_modeset::Mode| {
        let index = next_scanout;
        next_scanout = next_scanout.checked_add(1)?;
        let window = mtl_scanout_window(slot, stream)?;
        stream += 1;
        let width = u32::from(mode.h_active);
        let size = scanout_size_bytes(width, u32::from(mode.v_active));
        let reuse = if index == 0 {
            (*MTL_SCANOUT.lock())
                .filter(|(owner, retained)| *owner == bar && retained.size_bytes >= size)
                .map(|(_, retained)| retained)
        } else {
            MTL_EXTRA_SCANOUTS
                .lock()
                .iter()
                .find(|(owner, slot, retained)| {
                    *owner == bar && *slot == index && retained.size_bytes >= size
                })
                .map(|(_, _, retained)| *retained)
        };
        let allocation = match reuse {
            Some(retained) => retained,
            None => {
                let fresh = alloc(window, size)?;
                if index == 0 {
                    *MTL_SCANOUT.lock() = Some((bar, fresh));
                } else {
                    let mut surfaces = MTL_EXTRA_SCANOUTS.lock();
                    if let Some(entry) = surfaces
                        .iter_mut()
                        .find(|(owner, slot, _)| *owner == bar && *slot == index)
                    {
                        entry.2 = fresh;
                    } else {
                        surfaces.push((bar, index, fresh));
                    }
                }
                fresh
            }
        };
        Some(crate::intel_gpu_modeset::Framebuffer {
            phys_addr: u64::from(allocation.gtt_offset),
            stride_bytes: padded_stride_bytes(width),
            format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
        })
    };
    let outcome = crate::intel_gpu_xelpg_external::handle_mtl_event_for_profile(
        io,
        profile,
        event,
        display,
        &mut alloc_fb,
    );
    after_event();
    if let Some(ServiceOutcome::Activated { mode, fb, pipe, .. }) = outcome {
        let phys = if slot == 0 {
            (*MTL_SCANOUT.lock())
                .filter(|(owner, retained)| {
                    *owner == bar && u64::from(retained.gtt_offset) == fb.phys_addr
                })
                .map(|(_, retained)| retained.phys_base)
        } else {
            MTL_EXTRA_SCANOUTS
                .lock()
                .iter()
                .find(|(owner, key, retained)| {
                    *owner == bar
                        && *key == MTL_SECOND_SCANOUT_KEY
                        && u64::from(retained.gtt_offset) == fb.phys_addr
                })
                .map(|(_, _, retained)| retained.phys_base)
        };
        let serial = next_external_scanout_serial();
        if let (Some(phys), Some(serial)) = (phys, serial) {
            let image = narf_graphics_driver::generic::GenericFb::new(
                phys,
                u32::from(mode.h_active),
                u32::from(mode.v_active),
                fb.stride_bytes,
                32,
            );
            mtl_slot_serial(slot).store(serial, core::sync::atomic::Ordering::Release);
            MTL_SLOT_IMAGES.lock()[slot.min(1)] = Some((image, pipe));
            publication(MtlPublication::Publish(image, serial, pipe));
        }
    }
    withdraw_dark_mtl_slots(publication);
    true
}

/// Withdraw the image of every route slot whose route is no longer live
/// (serial-matched). When the withdrawn image was the active one and the
/// sibling route still scans out, the sibling's image takes the console
/// back under a fresh serial.
fn withdraw_dark_mtl_slots(publication: &mut dyn FnMut(MtlPublication)) {
    for slot in 0..2 {
        if crate::intel_gpu_xelpg_external::slot_live(slot) {
            continue;
        }
        let serial = mtl_slot_serial(slot).swap(0, core::sync::atomic::Ordering::AcqRel);
        if serial == 0 {
            continue;
        }
        MTL_SLOT_IMAGES.lock()[slot] = None;
        let active = ACTIVE_GENERIC.lock().0 == serial;
        publication(MtlPublication::Withdraw(serial));
        let sibling = 1 - slot;
        let image = MTL_SLOT_IMAGES.lock()[sibling];
        if let (true, true, Some((image, pipe))) = (
            active,
            crate::intel_gpu_xelpg_external::slot_live(sibling),
            image,
        ) {
            if let Some(serial) = next_external_scanout_serial() {
                mtl_slot_serial(sibling).store(serial, core::sync::atomic::Ordering::Release);
                publication(MtlPublication::Publish(image, serial, pipe));
            }
        }
    }
}

/// Generation-only adapter retained for the native runtime-hook fixtures.
/// Production uses [`mtl_external_pass_profile`] so WCL cannot be widened to
/// the broad Panther Lake profile.
#[cfg(any(test, feature = "kernel-test"))]
#[allow(clippy::too_many_arguments)]
fn mtl_external_pass<M: crate::intel_gpu_aux::MmioWindow + ?Sized>(
    io: &M,
    generation: Generation,
    bar: u64,
    display: &crate::intel_gpu_xelpg_external::MtlDisplay,
    before_event: &mut dyn FnMut(),
    after_event: &mut dyn FnMut(),
    alloc: &mut dyn FnMut(crate::intel_gpu_pipes::Pipe, u64) -> Option<ScanoutAllocation>,
    publication: &mut dyn FnMut(MtlPublication),
) -> bool {
    let Some(profile) =
        crate::intel_gpu_xelpg_external::ExternalDisplayProfile::for_generation(generation)
    else {
        return false;
    };
    mtl_external_pass_profile(
        io,
        profile,
        bar,
        display,
        before_event,
        after_event,
        alloc,
        publication,
    )
}

/// Production publication: the same ACTIVE + observer protocol and exact
/// serial-matched withdrawal the Gen12 SST owner uses; the image's pipe is
/// recorded for [`active_external_pipe`] before it becomes ACTIVE.
fn mtl_publish(request: MtlPublication) {
    match request {
        MtlPublication::Publish(fb, serial, pipe) => {
            MTL_PUBLISHED_PIPE.store(pipe as u8 + 1, core::sync::atomic::Ordering::Release);
            publish_external_scanout(fb, serial)
        }
        MtlPublication::Withdraw(serial) => {
            if withdraw_external_scanout(serial) {
                MTL_PUBLISHED_PIPE.store(0, core::sync::atomic::Ordering::Release);
            }
        }
    }
}

/// One production Display-14/20/30 external pass for the probed display.
fn service_mtl_display(before_event: &mut dyn FnMut(), after_event: &mut dyn FnMut()) -> bool {
    with_display_info(|gpu| {
        if !crate::intel_gpu_xelpg_hpd::hpd_generation_supported(gpu.chip.generation) {
            return false;
        }
        let gtt = gpu.gtt_mmadr;
        let kms = crate::intel_gpu_kms::display_for_bar(&gtt);
        if matches!(
            gpu.chip.generation,
            Generation::LunarLake | Generation::PantherLake
        ) && kms.is_none()
        {
            return false;
        }
        let display_ip = match gpu.chip.generation {
            Generation::MeteorLake => crate::intel_gpu_xe2lpd::DisplayIp::Xelpdp,
            Generation::LunarLake | Generation::PantherLake => {
                let Some(ip) = kms
                    .as_ref()
                    .and_then(|display| display.integrated_display_ip())
                else {
                    return false;
                };
                ip
            }
            _ => return false,
        };
        let profile = crate::intel_gpu_xelpg_external::ExternalDisplayProfile::for_ip(display_ip);
        let window = gpu.mode_window();
        // The owned panel the route adopts next to it, and the display-14/20/30
        // DC service's pipe-DMC sink.
        let display = crate::intel_gpu_xelpg_external::MtlDisplay::production(
            crate::intel_gpu_modeset_xelpg::owned_panel_mode(),
        );
        let xe2_scanout = matches!(
            gpu.chip.generation,
            Generation::LunarLake | Generation::PantherLake
        );
        // Each concurrently lit surface takes its own console GGTT window
        // (`mtl_scanout_window`).
        let mut alloc_fn = |window: crate::intel_gpu_pipes::Pipe, size| {
            let offset = crate::intel_gpu_multipipe::scanout_gtt_offset(window);
            let alloc = if xe2_scanout {
                crate::intel_gpu_gtt::alloc_contiguous_scanout_with_format(
                    &gtt,
                    offset,
                    size,
                    crate::intel_gpu_gtt::PteFormat::Xe2,
                    0,
                )
            } else {
                crate::intel_gpu_gtt::alloc_contiguous_scanout_at(&gtt, offset, size)
            }
            .ok()?;
            Some(ScanoutAllocation {
                gtt_offset: alloc.gtt_offset,
                phys_base: alloc.phys_base(),
                order: alloc.order,
                size_bytes: alloc.size_bytes,
            })
        };
        match gpu.chip.generation {
            // Display 35: port B and TC1/TC2 through the LT PHY, over the
            // display-35 view (PICA-relocated DDI B, no Wa_15015404425).
            Generation::PantherLake
                if display_ip == crate::intel_gpu_xe2lpd::DisplayIp::NovaLakeS =>
            {
                let view = crate::intel_gpu_xe3plpd::View(&window);
                mtl_external_pass_profile(
                    &view,
                    profile,
                    gtt.phys.raw(),
                    &display,
                    before_event,
                    after_event,
                    &mut alloc_fn,
                    &mut mtl_publish,
                )
            }
            Generation::LunarLake => {
                let view = crate::intel_gpu_xe2lpd::PicaFlushed(&window);
                mtl_external_pass_profile(
                    &view,
                    profile,
                    gtt.phys.raw(),
                    &display,
                    before_event,
                    after_event,
                    &mut alloc_fn,
                    &mut mtl_publish,
                )
            }
            Generation::PantherLake => {
                let flush = crate::intel_gpu_xe3lpd::wa_15015404425_active(&window);
                let view = crate::intel_gpu_xe3lpd::View::new(&window, flush)
                    .with_c20_port_b(profile.c20_port_b());
                mtl_external_pass_profile(
                    &view,
                    profile,
                    gtt.phys.raw(),
                    &display,
                    before_event,
                    after_event,
                    &mut alloc_fn,
                    &mut mtl_publish,
                )
            }
            _ => mtl_external_pass_profile(
                &window,
                profile,
                gtt.phys.raw(),
                &display,
                before_event,
                after_event,
                &mut alloc_fn,
                &mut mtl_publish,
            ),
        }
    })
    .unwrap_or(false)
}

/// Runtime-actor Display-14/20/30 external pass for `bar`, holding the panel's
/// KMS owner through [`crate::intel_gpu_kms::Device::external_pass`].
fn service_mtl_external_for_bar(bar: &MmioRegion) {
    let supported = with_display_info(|gpu| {
        crate::intel_gpu_xelpg_hpd::hpd_generation_supported(gpu.chip.generation)
            && gpu.gtt_mmadr.phys == bar.phys
    })
    .unwrap_or(false);
    if !supported {
        return;
    }
    let display = crate::intel_gpu_kms::display_for_bar(bar);
    let _ = mtl_runtime_pass(display.as_deref(), |before, after| {
        service_mtl_display(before, after)
    });
}

/// The runtime MTL pass's hold on the panel's KMS owner, around `pass` (the
/// hotplug poll and its event, given the pre- and post-update hooks):
/// [`crate::intel_gpu_kms::Device::external_pass`], which brackets FBC and
/// PSR around the event and never blocks the owner. A busy owner skips the
/// pass (`false`) before its poll; without a KMS owner the pass runs
/// unbracketed. Generic over the KMS platform so the native fixtures drive
/// exactly the body the runtime actor runs.
pub(crate) fn mtl_runtime_pass<M: crate::intel_gpu_kms::Platform>(
    display: Option<&crate::intel_gpu_kms::Device<M>>,
    pass: impl FnOnce(&mut dyn FnMut(), &mut dyn FnMut()) -> bool,
) -> bool {
    let owner = match display {
        Some(display) => match display.external_pass() {
            Ok(owner) => Some(owner),
            Err(_) => return false,
        },
        None => None,
    };
    let owner = core::cell::RefCell::new(owner);
    pass(
        &mut || {
            if let Some(owner) = owner.borrow_mut().as_mut() {
                owner.pre_update();
            }
        },
        &mut || {
            if let Some(owner) = owner.borrow_mut().as_mut() {
                owner.post_update();
            }
        },
    )
}

/// Suspend/GT-reset retirement of the MTL route and its hotplug sources,
/// then withdrawal of its publication once nothing is live. `Busy` when a
/// route stays retained (quarantined or a service pass in progress).
pub(crate) async fn retire_mtl_external(bar: &MmioRegion) -> Result<(), narf_filesystem::FsError> {
    let Some(gpu) = with_display_info(|gpu| *gpu).filter(|gpu| {
        gpu.gtt_mmadr.phys == bar.phys
            && crate::intel_gpu_xelpg_hpd::hpd_generation_supported(gpu.chip.generation)
    }) else {
        return Ok(());
    };
    let display = crate::intel_gpu_kms::display_for_bar(bar);
    let _pass = match display.as_ref() {
        Some(display) => Some(
            display
                .external_retirement(crate::intel_gpu_xelpg_external::routes_stopped)
                .await?,
        ),
        None => None,
    };
    // Display 35's route stops through the view it was lit over: DDI B's
    // PHY and AUX in PICA, the LT PHY behind it.
    let nova = display
        .as_ref()
        .and_then(|display| display.integrated_display_ip())
        == Some(crate::intel_gpu_xe2lpd::DisplayIp::NovaLakeS);
    let window = gpu.mode_window();
    let done = if nova {
        crate::intel_gpu_xelpg_external::teardown_mtl_external(
            &crate::intel_gpu_xe3plpd::View(&window),
            gpu.chip.generation,
        )
    } else {
        crate::intel_gpu_xelpg_external::teardown_mtl_external(&window, gpu.chip.generation)
    };
    withdraw_dark_mtl_slots(&mut mtl_publish);
    if done {
        Ok(())
    } else {
        Err(narf_filesystem::FsError::Busy)
    }
}
/// Caller holds the same display legacy guard used by physical device PM.
/// Never waits for another executor task or opens admission after Busy.
pub(crate) fn stop_external_sst_locked(bar: &MmioRegion) -> Result<(), narf_filesystem::FsError> {
    if unsupported_external_for_bar(bar) {
        return Err(narf_filesystem::FsError::Busy);
    }
    if step_external_sst_inner(bar, true)? {
        Ok(())
    } else {
        Err(narf_filesystem::FsError::Busy)
    }
}
/// Explicit PM/reset drain. Dropping the future leaves the same retained phase.
pub(crate) async fn retire_external_sst(bar: &MmioRegion) -> Result<(), narf_filesystem::FsError> {
    let lock_deadline = narf_time::monotonic_ns().saturating_add(50_000_000);
    loop {
        match step_external_sst(bar, true) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(narf_filesystem::FsError::Busy) => {
                if narf_time::monotonic_ns() >= lock_deadline {
                    return Err(narf_filesystem::FsError::Busy);
                }
            }
            Err(e) => return Err(e),
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(250).as_instant()).await;
    }
}

// ── DP MST session (lane Q11, #1017) ─────────────────────────
//
// The MST counterpart of the SST glue above: `intel_gpu_mst`
// owns the session logic (topology, payload allocation,
// per-stream modesets); this glue owns the controller-bound
// parts — pipe claims, per-pipe scanout windows and
// allocations, DBUF reprogramming as the active set changes,
// and fb-console publication of the first stream (the
// publication slot is single; see the SST section's note).

/// Per-stream glue state: the retained allocation and
/// framebuffer for one live MST stream.
struct MstStreamGlue {
    sink: crate::dp_mst_mgr::Sink,
    mode: crate::intel_gpu_modeset::Mode,
    fb: crate::intel_gpu_modeset::Framebuffer,
    alloc: ScanoutAllocation,
}

/// Live MST session state for one DDI.
struct MstSessionState {
    bar: u64,
    link: crate::intel_gpu_mst::MstLink,
    streams: alloc::vec::Vec<MstStreamGlue>,
}

static MST_SESSION: IrqSafeSpinLock<Option<MstSessionState>> = IrqSafeSpinLock::new(None);

/// The DDI the live MST session sits on, if any.
fn mst_session_ddi() -> Option<crate::intel_gpu_ddi::Ddi> {
    MST_SESSION.lock().as_ref().map(|s| s.link.ddi())
}

/// Try to bring an MST session up on `ddi`. Returns `false`
/// (leaving no trace — MST is stopped again, no pipe claimed)
/// when the device doesn't advertise MST, the topology probe
/// fails, or no sink stream could be lit; the caller then
/// falls back to the SST connect.
fn mst_connect(ddi: crate::intel_gpu_ddi::Ddi) -> bool {
    use crate::dp_aux::AuxChannel as _;
    // One MST link at a time: a second hub never replaces a live one.
    if MST_SESSION.lock().is_some() {
        return false;
    }
    let state = with_display_info(|gpu| {
        if !gpu.chip.generation.external_display_supported() {
            return None;
        }
        let window = gpu.mode_window();
        crate::intel_gpu_aux::SourceFamily::of(&window)?;
        // Capability gate: DP 1.2+ and MSTM_CAP set. Anything
        // less is an SST device and not this path's business.
        let mut aux = crate::intel_gpu_aux::IntelAux::new(&window, ddi);
        let raw_caps = crate::dp_link_training::read_receiver_caps(&mut aux).ok()?;
        let caps = crate::dp_link_training::DpcdCaps::decode(&raw_caps);
        let mut mstm_cap = [0u8; 1];
        aux.dpcd_read(crate::dp_mst_mgr::MSTM_CAP, &mut mstm_cap)
            .ok()?;
        if caps.dpcd_rev < 0x12 || mstm_cap[0] & 1 == 0 {
            return None;
        }

        let mut maux = crate::intel_gpu_mst::IntelMstAux::new(&window, ddi);
        let mut link = crate::intel_gpu_mst::MstLink::new(ddi);
        if link.connect(&window, &mut maux, caps, &raw_caps).is_err() {
            return None;
        }
        if link.probe_topology(&mut maux).is_err() {
            let _ = link.disconnect(&window, &mut maux);
            return None;
        }
        let sinks = link.topology().map(|t| t.sinks()).unwrap_or_default();
        let mut streams: alloc::vec::Vec<MstStreamGlue> = alloc::vec::Vec::new();
        for sink in sinks {
            let Some(pipe) =
                crate::intel_gpu_multipipe::claim_any_pipe(crate::intel_gpu_multipipe::PipeOwner {
                    ddi,
                    used_for: crate::intel_gpu_multipipe::PipeUse::ExternalMst,
                })
            else {
                break;
            };
            let mode = match link.sink_mode(&mut maux, sink) {
                Ok(mode) => mode,
                Err(_) => {
                    crate::intel_gpu_multipipe::release_pipe(pipe, ddi);
                    continue;
                }
            };
            let width = mode.h_active as u32;
            let height = mode.v_active as u32;
            let stride_bytes = padded_stride_bytes(width);
            let size_bytes = scanout_size_bytes(width, height);
            let alloc = match crate::intel_gpu_gtt::alloc_contiguous_scanout_at(
                &gpu.gtt_mmadr,
                crate::intel_gpu_multipipe::scanout_gtt_offset(pipe),
                size_bytes,
            ) {
                Ok(alloc) => ScanoutAllocation {
                    gtt_offset: alloc.gtt_offset,
                    phys_base: alloc.phys_base(),
                    order: alloc.order,
                    size_bytes: alloc.size_bytes,
                },
                Err(_) => {
                    crate::intel_gpu_multipipe::release_pipe(pipe, ddi);
                    continue;
                }
            };
            let fb = crate::intel_gpu_modeset::Framebuffer {
                phys_addr: alloc.gtt_offset as u64,
                stride_bytes,
                format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
            };
            let share = {
                let active = crate::intel_gpu_multipipe::active_pipes();
                if active.len() >= 2 {
                    crate::intel_gpu_multipipe::share_for(&window, &active, pipe)
                } else {
                    None
                }
            };
            match link.add_stream(&window, &mut maux, sink, mode, pipe, &fb, share) {
                Ok(_) => {
                    streams.push(MstStreamGlue {
                        sink,
                        mode,
                        fb,
                        alloc,
                    });
                    crate::intel_gpu_multipipe::reprogram_active_dbuf_shares(&window);
                }
                Err(_) => {
                    crate::intel_gpu_multipipe::release_pipe(pipe, ddi);
                }
            }
        }
        if streams.is_empty() {
            // Nothing lit: not an MST session. Stop MST so the
            // branch presents as an SST device to the fallback.
            let _ = link.disconnect(&window, &mut maux);
            return None;
        }
        Some(MstSessionState {
            bar: gpu.gtt_mmadr.phys.raw(),
            link,
            streams,
        })
    })
    .flatten();
    match state {
        Some(state) => {
            *MST_SESSION.lock() = Some(state);
            true
        }
        None => false,
    }
}

/// Tear the MST session on `ddi` down: streams in reverse
/// bring-up order (payloads deallocated, pipes torn down),
/// MST off, pipes released.
fn mst_disconnect(ddi: crate::intel_gpu_ddi::Ddi) -> bool {
    let state = {
        let mut session = MST_SESSION.lock();
        match session.as_ref() {
            Some(s) if s.link.ddi() == ddi => session.take(),
            _ => None,
        }
    };
    let Some(mut state) = state else {
        return false;
    };
    let stopped = with_display_info(|gpu| {
        let window = gpu.mode_window();
        if crate::intel_gpu_aux::SourceFamily::of(&window) != state.link.family() {
            return false;
        }
        let mut maux = crate::intel_gpu_mst::IntelMstAux::new(&window, ddi);
        while let Some(glue) = state.streams.last() {
            let stream = match state.link.remove_stream(&window, &mut maux, glue.sink) {
                Ok(stream) => stream,
                Err(_) => return false,
            };
            // Preserve progress if a later drain is refused: removed streams
            // are never replayed against a retained partially drained link.
            state.streams.pop();
            crate::intel_gpu_multipipe::release_pipe(stream.pipe, ddi);
        }
        if state.link.disconnect(&window, &mut maux).is_err() {
            return false;
        }
        crate::intel_gpu_multipipe::reprogram_active_dbuf_shares(&window);
        true
    })
    .unwrap_or(false);
    if !stopped {
        *MST_SESSION.lock() = Some(state);
    }
    stopped
}

/// Drain branch notifications for the MST session on `ddi`
/// (the RetrainRequired route). Events are logged; acting on
/// a vanished sink beyond the log is the session layer's next
/// step, not this glue's.
fn mst_poll_notifications(ddi: crate::intel_gpu_ddi::Ddi) {
    use core::fmt::Write as _;
    let state = {
        let mut session = MST_SESSION.lock();
        match session.as_ref() {
            Some(s) if s.link.ddi() == ddi => session.take(),
            _ => None,
        }
    };
    let Some(mut state) = state else { return };
    with_display_info(|gpu| {
        let window = gpu.mode_window();
        if crate::intel_gpu_aux::SourceFamily::of(&window) != state.link.family() {
            return;
        }
        let mut maux = crate::intel_gpu_mst::IntelMstAux::new(&window, ddi);
        if let Ok(events) = state.link.poll_notifications(&mut maux) {
            for event in events {
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gpu: MST event on DDI {:?}: {:?}",
                    ddi,
                    event,
                );
            }
        }
    });
    // Restore the session (teardown races are the HPD
    // sequencer's problem, exactly as in the SST retrain path:
    // the store-back is unconditional).
    let mut session = MST_SESSION.lock();
    if session.is_none() {
        *session = Some(state);
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Cross-crate native fixture hook: exercises the real CPU-view gate,
    /// without constructing a PCI display or pretending any GEM DMA retired.
    pub async fn kms_pause_console_for_test() {
        super::kms_pause_console().await;
    }

    /// The calling fixture owns its synthetic CPU scanout and proves it
    /// never armed GEM fetch before reopening the real writer gate.
    pub fn kms_resume_console_for_test() {
        super::kms_resume_console();
    }

    fn smoke_kms_console_pause_drains_views_and_survives_cancel() -> TestResult {
        use core::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        if kms_console_paused() {
            return TestResult::Skip("a production KMS session owns the console");
        }
        let installed = narf_graphics::console::GLOBAL_FB_CONSOLE.lock().is_some();
        // SAFETY: only a scalar is captured; no mapping access escapes.
        let old = unsafe { crate::scanout_access::snapshot(|| 7) };
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut pause = core::pin::pin!(kms_pause_console());
            assert_eq!(pause.as_mut().poll(&mut cx), Poll::Pending);
            assert!(kms_console_paused());
            assert!(narf_graphics::console::GLOBAL_FB_CONSOLE.lock().is_none());
        }
        // Cancellation does not reopen writers while a previous CPU view
        // can still write. A later waiter must observe that same old view.
        assert!(kms_console_paused());
        let mut pause = core::pin::pin!(kms_pause_console());
        assert_eq!(pause.as_mut().poll(&mut cx), Poll::Pending);
        // A post-pause view sees the gate under the same epoch lock and
        // must not delay retirement of the prior display's writers.
        // SAFETY: only the admission boolean is captured, with no raw mapping.
        let current = unsafe { crate::scanout_access::snapshot(kms_console_paused) };
        assert!(*current);
        drop(old);
        assert_eq!(pause.as_mut().poll(&mut cx), Poll::Ready(()));
        drop(current);
        kms_resume_console();
        assert!(!kms_console_paused());
        assert_eq!(
            narf_graphics::console::GLOBAL_FB_CONSOLE.lock().is_some(),
            installed
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_kms",
        smoke_kms_console_pause_drains_views_and_survives_cancel
    );

    /// Census: the canonical table must contain exactly the DID
    /// set transcribed from spec §5 / Linux `pciids.h`, every row
    /// must classify back to its own (generation, asic), and no
    /// DID or registration name may repeat. If a SKU is added or
    /// dropped, this fixture and spec §5 must move together.
    fn smoke_device_table_census() -> TestResult {
        // (did, asic) — transcribed from drivers/gpu/specification/intel_gpu.md §5.
        const EXPECTED: &[(u16, &str)] = &[
            (0x6420, "lunarlake"),
            (0x64a0, "lunarlake"),
            (0x64b0, "lunarlake"),
            (0x1902, "skylake"),
            (0x1906, "skylake"),
            (0x190A, "skylake"),
            (0x190B, "skylake"),
            (0x190E, "skylake"),
            (0x1912, "skylake"),
            (0x1913, "skylake"),
            (0x1915, "skylake"),
            (0x1916, "skylake"),
            (0x1917, "skylake"),
            (0x191A, "skylake"),
            (0x191B, "skylake"),
            (0x191D, "skylake"),
            (0x191E, "skylake"),
            (0x1921, "skylake"),
            (0x1923, "skylake"),
            (0x1926, "skylake"),
            (0x1927, "skylake"),
            (0x192A, "skylake"),
            (0x192B, "skylake"),
            (0x192D, "skylake"),
            (0x1932, "skylake"),
            (0x193A, "skylake"),
            (0x193B, "skylake"),
            (0x193D, "skylake"),
            (0x5902, "kabylake"),
            (0x5906, "kabylake"),
            (0x5908, "kabylake"),
            (0x590A, "kabylake"),
            (0x590B, "kabylake"),
            (0x590E, "kabylake"),
            (0x5912, "kabylake"),
            (0x5913, "kabylake"),
            (0x5915, "kabylake"),
            (0x5916, "kabylake"),
            (0x5917, "kabylake"),
            (0x591A, "kabylake"),
            (0x591B, "kabylake"),
            (0x591C, "kabylake"),
            (0x591D, "kabylake"),
            (0x591E, "kabylake"),
            (0x5921, "kabylake"),
            (0x5923, "kabylake"),
            (0x5926, "kabylake"),
            (0x5927, "kabylake"),
            (0x593B, "kabylake"),
            (0x87C0, "kabylake"),
            (0x3E90, "coffeelake"),
            (0x3E91, "coffeelake"),
            (0x3E92, "coffeelake"),
            (0x3E93, "coffeelake"),
            (0x3E94, "coffeelake"),
            (0x3E96, "coffeelake"),
            (0x3E98, "coffeelake"),
            (0x3E99, "coffeelake"),
            (0x3E9A, "coffeelake"),
            (0x3E9B, "coffeelake"),
            (0x3E9C, "coffeelake"),
            (0x3EA5, "coffeelake"),
            (0x3EA6, "coffeelake"),
            (0x3EA7, "coffeelake"),
            (0x3EA8, "coffeelake"),
            (0x3EA9, "coffeelake"),
            (0x87CA, "coffeelake"),
            (0x3EA0, "whiskeylake"),
            (0x3EA1, "whiskeylake"),
            (0x3EA2, "whiskeylake"),
            (0x3EA3, "whiskeylake"),
            (0x3EA4, "whiskeylake"),
            (0x9B21, "cometlake"),
            (0x9B41, "cometlake"),
            (0x9BA2, "cometlake"),
            (0x9BA4, "cometlake"),
            (0x9BA5, "cometlake"),
            (0x9BA8, "cometlake"),
            (0x9BAA, "cometlake"),
            (0x9BAC, "cometlake"),
            (0x9BC2, "cometlake"),
            (0x9BC4, "cometlake"),
            (0x9BC5, "cometlake"),
            (0x9BC6, "cometlake"),
            (0x9BC8, "cometlake"),
            (0x9BCA, "cometlake"),
            (0x9BCC, "cometlake"),
            (0x9BE6, "cometlake"),
            (0x9BF6, "cometlake"),
            (0x0A84, "broxton"),
            (0x1A84, "broxton"),
            (0x1A85, "broxton"),
            (0x5A84, "broxton"),
            (0x5A85, "broxton"),
            (0x3184, "geminilake"),
            (0x3185, "geminilake"),
            (0x8A50, "icelake"),
            (0x8A51, "icelake"),
            (0x8A52, "icelake"),
            (0x8A53, "icelake"),
            (0x8A54, "icelake"),
            (0x8A56, "icelake"),
            (0x8A57, "icelake"),
            (0x8A58, "icelake"),
            (0x8A59, "icelake"),
            (0x8A5A, "icelake"),
            (0x8A5B, "icelake"),
            (0x8A5C, "icelake"),
            (0x8A5D, "icelake"),
            (0x8A70, "icelake"),
            (0x8A71, "icelake"),
            (0x4541, "elkhartlake"),
            (0x4551, "elkhartlake"),
            (0x4555, "elkhartlake"),
            (0x4557, "elkhartlake"),
            (0x4570, "elkhartlake"),
            (0x4571, "elkhartlake"),
            (0x4E51, "jasperlake"),
            (0x4E55, "jasperlake"),
            (0x4E57, "jasperlake"),
            (0x4E61, "jasperlake"),
            (0x4E71, "jasperlake"),
            (0x9A40, "tigerlake"),
            (0x9A49, "tigerlake"),
            (0x9A59, "tigerlake"),
            (0x9A60, "tigerlake"),
            (0x9A68, "tigerlake"),
            (0x9A70, "tigerlake"),
            (0x9A78, "tigerlake"),
            (0x9AC0, "tigerlake"),
            (0x9AC9, "tigerlake"),
            (0x9AD9, "tigerlake"),
            (0x9AF8, "tigerlake"),
            (0x4C80, "rocketlake"),
            (0x4C8A, "rocketlake"),
            (0x4C8B, "rocketlake"),
            (0x4C8C, "rocketlake"),
            (0x4C90, "rocketlake"),
            (0x4C9A, "rocketlake"),
            (0x4626, "alderlake-p"),
            (0x4628, "alderlake-p"),
            (0x462A, "alderlake-p"),
            (0x4636, "alderlake-p"),
            (0x4638, "alderlake-p"),
            (0x463A, "alderlake-p"),
            (0x46A0, "alderlake-p"),
            (0x46A1, "alderlake-p"),
            (0x46A2, "alderlake-p"),
            (0x46A3, "alderlake-p"),
            (0x46A6, "alderlake-p"),
            (0x46A8, "alderlake-p"),
            (0x46AA, "alderlake-p"),
            (0x46B6, "alderlake-p"),
            (0x46B8, "alderlake-p"),
            (0x46BA, "alderlake-p"),
            (0x46B0, "alderlake-p"),
            (0x46B1, "alderlake-p"),
            (0x46B2, "alderlake-p"),
            (0x46B3, "alderlake-p"),
            (0x46C0, "alderlake-m"),
            (0x46C1, "alderlake-m"),
            (0x46C2, "alderlake-m"),
            (0x46C3, "alderlake-m"),
            (0x46D0, "alderlake-n"),
            (0x46D1, "alderlake-n"),
            (0x46D2, "alderlake-n"),
            (0x46D3, "alderlake-n"),
            (0x46D4, "alderlake-n"),
            (0x4680, "alderlake-s"),
            (0x4682, "alderlake-s"),
            (0x4688, "alderlake-s"),
            (0x468A, "alderlake-s"),
            (0x468B, "alderlake-s"),
            (0x4690, "alderlake-s"),
            (0x4692, "alderlake-s"),
            (0x4693, "alderlake-s"),
            (0xA780, "raptorlake-s"),
            (0xA781, "raptorlake-s"),
            (0xA782, "raptorlake-s"),
            (0xA783, "raptorlake-s"),
            (0xA788, "raptorlake-s"),
            (0xA789, "raptorlake-s"),
            (0xA78A, "raptorlake-s"),
            (0xA78B, "raptorlake-s"),
            (0xA720, "raptorlake-p"),
            (0xA721, "raptorlake-u"),
            (0xA7A0, "raptorlake-p"),
            (0xA7A1, "raptorlake-u"),
            (0xA7A8, "raptorlake-p"),
            (0xA7A9, "raptorlake-u"),
            (0xA7AA, "raptorlake-p"),
            (0xA7AB, "raptorlake-p"),
            (0xA7AC, "raptorlake-u"),
            (0xA7AD, "raptorlake-u"),
            (0x7D40, "meteorlake"),
            (0x7D45, "meteorlake"),
            (0x7D55, "meteorlake"),
            (0x7D60, "meteorlake"),
            (0x7DD5, "meteorlake"),
            (0x7D41, "arrowlake"),
            (0x7D51, "arrowlake"),
            (0x7D67, "arrowlake"),
            (0x7DD1, "arrowlake"),
            (0xB640, "arrowlake"),
            (0xB080, "pantherlake"),
            (0xB081, "pantherlake"),
            (0xB082, "pantherlake"),
            (0xB083, "pantherlake"),
            (0xB084, "pantherlake"),
            (0xB085, "pantherlake"),
            (0xB086, "pantherlake"),
            (0xB087, "pantherlake"),
            (0xB08F, "pantherlake"),
            (0xB090, "pantherlake"),
            (0xB0A0, "pantherlake"),
            (0xB0A1, "pantherlake"),
            (0xB0B0, "pantherlake"),
            (0xFD80, "wildcatlake"),
            (0xFD81, "wildcatlake"),
            (0xD740, "novalake-s"),
            (0xD741, "novalake-s"),
            (0xD742, "novalake-s"),
            (0xD743, "novalake-s"),
            (0xD744, "novalake-s"),
            (0xD745, "novalake-s"),
            (0xD74A, "novalake-s"),
            (0xD74B, "novalake-s"),
        ];
        if DEVICE_TABLE.len() != EXPECTED.len() {
            return TestResult::Fail("device table size drifted from the spec §5 census");
        }
        for (did, asic) in EXPECTED {
            let info = match chip_info_for_pci_id(INTEL_VENDOR, *did) {
                Some(i) => i,
                None => return TestResult::Fail("census DID does not classify"),
            };
            if info.asic != *asic || info.did != *did {
                return TestResult::Fail("census DID classifies to the wrong ASIC");
            }
            let platform = crate::intel_gpu_gt::GtPlatform::from_pci(INTEL_VENDOR, *did);
            if matches!(
                *asic,
                "alderlake-p" | "alderlake-m" | "raptorlake-p" | "raptorlake-u"
            ) && crate::intel_gpu_modeset::gen12_family_for_chip(info)
                != Some(crate::intel_gpu_gt::Gen12Platform::AlderLakeP)
            {
                return TestResult::Fail("mobile ADL/RPL must use the ADL-P display profile");
            }
            if platform
                .and_then(crate::intel_gpu_gt::GtPlatform::guc)
                .is_none()
            {
                return TestResult::Fail("census DID has no qualified GT/GuC profile");
            }
        }
        // No duplicate DIDs or registration names.
        for (i, a) in DEVICE_TABLE.iter().enumerate() {
            for b in DEVICE_TABLE.iter().skip(i + 1) {
                if a.did == b.did {
                    return TestResult::Fail("duplicate DID in device table");
                }
                if a.name == b.name {
                    return TestResult::Fail("duplicate registration name in device table");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu", smoke_device_table_census);

    fn smoke_unknown_ids_do_not_classify() -> TestResult {
        if chip_info_for_pci_id(INTEL_VENDOR, 0x1234).is_some() {
            return TestResult::Fail("unknown Intel DID must not classify");
        }
        if chip_info_for_pci_id(0x10DE, TGL_U_GT2_9A49).is_some() {
            return TestResult::Fail("non-Intel vendor must not classify");
        }
        // Exact IDs only: nearby values outside Linux's family macros must
        // not bleed into a platform profile through an approximate range.
        for did in [
            0x9A5Au16, 0x9ACA, 0x4C81, 0x46A4, 0x46B4, 0x46C4, 0xFD82, 0xD746, 0x8A5E, 0x8A5F,
            0x4572, 0x4E52,
        ] {
            if chip_info_for_pci_id(INTEL_VENDOR, did).is_some() {
                return TestResult::Fail("unlisted DID present in table");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu", smoke_unknown_ids_do_not_classify);

    #[cfg(feature = "kernel-test")]
    fn smoke_unqualified_class_probe_preserves_pci_command() -> TestResult {
        use narf_bus::{BusAddr, BusKind, DeviceId, PcieAddr, ProbeError};
        let addr = PcieAddr::new(0x7f35, 0, 2, 0);
        let cfg_phys = narf_memory::PhysAddr::new(0x7f35_0000);
        let mut config = alloc::vec![0u32; 1024];
        // SAFETY: the scoped ECAM window points at this test's aligned
        // RAM and is removed before the backing vector drops.
        let _window = unsafe {
            narf_bus::ecam::__test_windows(&[(cfg_phys, config.as_mut_ptr().cast(), 4096)])
        };
        config[1] = 1; // firmware left I/O-space decoding enabled
        for did in [0x46b4, 0xd746, 0xd74c, 0xd758, 0xb0a2]
            .into_iter()
            .chain(CRI_IDS.iter().chain(NVLP_IDS).copied())
        {
            let device = BusDevice {
                addr: BusAddr::Pcie(addr),
                kind: BusKind::Pcie { addr, cfg_phys },
                id: DeviceId {
                    vendor: INTEL_VENDOR,
                    device: did,
                    class: 0x030000,
                    subsystem_vendor: 0,
                    subsystem_id: 0,
                },
            };
            let cap = Cap::<BusDeviceCap, Write>::bootstrap();
            let result = probe(device, cap);
            cap.revoke();
            if !matches!(result, Err(ProbeError::NotForThisDriver)) || config[1] != 1 {
                return TestResult::Fail(
                    "unqualified Intel class probe claimed or reconfigured a device",
                );
            }
        }
        TestResult::Pass
    }
    #[cfg(feature = "kernel-test")]
    kernel_test_in!(
        "drivers/gpu/intel_gpu",
        smoke_unqualified_class_probe_preserves_pci_command
    );

    fn smoke_crescent_island_identity_is_exact_and_fail_closed() -> TestResult {
        for (ids, family) in [
            (
                &[0x674c, 0x674d, 0x674e, 0x674f, 0x6750][..],
                "Crescent Island",
            ),
            (
                &[
                    0xd750, 0xd751, 0xd752, 0xd753, 0xd754, 0xd755, 0xd756, 0xd757, 0xd75f,
                ][..],
                "Nova Lake-P",
            ),
        ] {
            for &did in ids {
                if !unqualified_probe_message(did).is_some_and(|message| message.contains(family))
                    || chip_info_for_pci_id(INTEL_VENDOR, did).is_some()
                    || crate::intel_gpu_gt::GtPlatform::from_pci(INTEL_VENDOR, did).is_some()
                {
                    return TestResult::Fail("unqualified PCI family entered an active profile");
                }
            }
        }
        for did in [0x674b, 0x6751, 0xd74f, 0xd758, 0xd75e, 0xd760] {
            if unqualified_probe_message(did).is_some() {
                return TestResult::Fail(
                    "neighboring PCI ID classified as Crescent Island or Nova Lake-P",
                );
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_crescent_island_identity_is_exact_and_fail_closed
    );

    fn smoke_arctic_sound_m_identity_is_exact_and_pf_only() -> TestResult {
        for did in [ATSM_56C0, ATSM_56C1, ATSM_56C2] {
            if unqualified_probe_message(did).is_some()
                || chip_info_for_pci_id(INTEL_VENDOR, did).is_some()
                || crate::intel_gpu_gt::GtPlatform::from_pci(INTEL_VENDOR, did)
                    != Some(crate::intel_gpu_gt::GtPlatform::ArcticSoundM)
            {
                return TestResult::Fail("Arctic Sound-M typed PF identity boundary");
            }
        }
        for did in [0x56bfu16, 0x56c3] {
            if unqualified_probe_message(did).is_some()
                || crate::intel_gpu_gt::GtPlatform::from_pci(INTEL_VENDOR, did)
                    == Some(crate::intel_gpu_gt::GtPlatform::ArcticSoundM)
            {
                return TestResult::Fail("Arctic Sound-M identity widened beyond Linux IDs");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_arctic_sound_m_identity_is_exact_and_pf_only
    );

    fn smoke_headless_gt_requires_every_display_fetcher_stopped() -> TestResult {
        use crate::intel_gpu_pipes::{PIPECONF_ENABLE, PIPECONF_STATE};
        if !display_fetchers_stopped_values([0; 4]) {
            return TestResult::Fail("four stopped pipes must admit a display-less GT");
        }
        for index in 0..4 {
            for bit in [PIPECONF_ENABLE, PIPECONF_STATE] {
                let mut pipeconf = [0; 4];
                pipeconf[index] = bit;
                if display_fetchers_stopped_values(pipeconf) {
                    return TestResult::Fail("any live or draining pipe must retain the GT gate");
                }
            }
        }
        if display_fetchers_stopped_values([0, 0, 0, u32::MAX]) {
            return TestResult::Fail("an unavailable pipe register must fail closed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu",
        smoke_headless_gt_requires_every_display_fetcher_stopped
    );

    /// The Gen9/Gen11 execlists owner coexists with a lit display only while
    /// every enabled plane and cursor fetches below the GT arena.
    fn smoke_execlists_gt_needs_planes_below_arena() -> TestResult {
        struct Regs(alloc::collections::BTreeMap<u64, u32>);
        impl crate::intel_gpu_aux::MmioWindow for Regs {
            fn read32(&self, off: u64) -> u32 {
                *self.0.get(&off).unwrap_or(&0)
            }
            fn write32(&self, _: u64, _: u32) {}
        }
        let lit = |plane: u64, surf: u32| {
            Regs(alloc::collections::BTreeMap::from([
                (plane, 1 << 31),
                (plane + 0x1c, surf),
            ]))
        };
        // GOP scanout at GGTT 0 on pipe A plane 1, the driver's at 16 MiB.
        if !legacy_planes_below_arena(&Regs(Default::default()))
            || !legacy_planes_below_arena(&lit(0x70180, 0))
            || !legacy_planes_below_arena(&lit(0x71180, 0x0100_0000))
            || !legacy_planes_below_arena(&lit(0x72780, 0x0bff_f000))
        {
            return TestResult::Fail("planes below the arena admit the owner");
        }
        // A plane, or Ice Lake's seventh plane, too close to 256 MiB; a
        // disabled plane's stale address does not count.
        if legacy_planes_below_arena(&lit(0x70180, 0x0c00_0000))
            || legacy_planes_below_arena(&lit(0x72780, 0x1000_0000))
            || !legacy_planes_below_arena(&Regs(alloc::collections::BTreeMap::from([(
                0x7019c,
                0x2000_0000,
            )])))
        {
            return TestResult::Fail("a plane near or in the arena refuses the owner");
        }
        let cursor = Regs(alloc::collections::BTreeMap::from([
            (0x71080, 0x27),
            (0x71084, 0x1000_0000),
        ]));
        let gone = Regs(alloc::collections::BTreeMap::from([(0x70180, u32::MAX)]));
        if legacy_planes_below_arena(&cursor) || legacy_planes_below_arena(&gone) {
            return TestResult::Fail("a cursor in the arena or an absent display refuses");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu",
        smoke_execlists_gt_needs_planes_below_arena
    );

    /// Regression for the 1366-wide panel panic: the unpadded
    /// stride (5464) is not 64-byte aligned and the plane builder
    /// rejects it; the padded stride (5504) must be accepted and
    /// the allocation sized by it.
    fn smoke_probe_stride_1366_regression() -> TestResult {
        if padded_stride_bytes(1366) != 5504 {
            return TestResult::Fail("1366-wide stride must pad to 5504");
        }
        if padded_stride_bytes(1920) != 7680 {
            return TestResult::Fail("1920-wide stride is already aligned");
        }
        if scanout_size_bytes(1366, 768) != 5504 * 768 {
            return TestResult::Fail("scanout size must use the padded stride");
        }
        match crate::intel_gpu_pipes::build_primary_plane(
            1366,
            768,
            1366 * 4,
            0x10_0000,
            crate::intel_gpu_pipes::PixelFormat::Argb8888,
        ) {
            Err(crate::intel_gpu_pipes::PipeError::BadStride) => {}
            _ => return TestResult::Fail("unpadded 1366 stride must be rejected"),
        }
        if crate::intel_gpu_pipes::build_primary_plane(
            1366,
            768,
            padded_stride_bytes(1366),
            0x10_0000,
            crate::intel_gpu_pipes::PixelFormat::Argb8888,
        )
        .is_err()
        {
            return TestResult::Fail("padded 1366 stride must build a plane");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu", smoke_probe_stride_1366_regression);

    fn smoke_display_generation_gates() -> TestResult {
        if !Generation::TigerLake.display_supported() || !Generation::AlderLake.display_supported()
        {
            return TestResult::Fail("Gen12 generations must allow display programming");
        }
        // #1016: Meteor Lake's Xe-LPG sequence is implemented, so
        // the gate opens for MTL. Lunar Lake (Xe2-LPD) and Panther
        // Lake (Xe3-LPD) stay gated off on this predicate even
        // though their display is driven: each has its own
        // opted-in per-device route, and this predicate gates the
        // Gen12/MTL probe branch that precedes those routes —
        // flipping it would run the Gen12 takeover (which refuses
        // both) instead of the owned route, and arm refused PSR.
        if !Generation::MeteorLake.display_supported() {
            return TestResult::Fail("MTL must allow display programming (#1016)");
        }
        if Generation::LunarLake.display_supported() || Generation::PantherLake.display_supported()
        {
            return TestResult::Fail("LNL/PTL must skip the Gen12/MTL probe path (owned routes)");
        }
        if Generation::RocketLake.display_supported()
            || !Generation::RocketLake.external_display_supported()
            || Generation::RocketLake.backlight_supported()
            || Generation::RocketLake.region_generation() != Some(RegionGeneration::Gen12)
        {
            return TestResult::Fail(
                "RKL must admit Gen12 GT regions and external outputs while the panel stays gated",
            );
        }
        // Gen9 (Lanes 1 + 5 + 8): identity + probe +
        // internal-panel modeset + external outputs +
        // backlight. The BAR0 region map is admitted (Gen9
        // shares Gen12's partitioning) and the part is
        // explicitly pre-GMD; display, external display and
        // backlight are admitted (fixture-validated, silicon
        // untested). The HPD/session layer still fails closed
        // for Gen9 (its own Gen12 gates), so this flip arms no
        // session path. The part still binds and announces.
        if !Generation::Skylake.display_supported()
            || !Generation::Skylake.external_display_supported()
            || !Generation::Skylake.backlight_supported()
            || Generation::Skylake.region_generation() != Some(RegionGeneration::Gen9)
            || Generation::Skylake.has_gmd_id()
        {
            return TestResult::Fail("Gen9 must admit regions + display + external + backlight");
        }
        // Gen9 LP: the Gen9 register map, pre-GMD, the internal panel with
        // its BXT-layout backlight, and DP/HDMI on DDI B and C.
        if !Generation::Broxton.display_supported()
            || !Generation::Broxton.external_display_supported()
            || !Generation::Broxton.backlight_supported()
            || Generation::Broxton.region_generation() != Some(RegionGeneration::Gen9)
            || Generation::Broxton.has_gmd_id()
        {
            return TestResult::Fail("Gen9 LP drives its panel and external DDIs");
        }
        // Gen11 (Lanes 5 + 8): identity + probe + internal-panel
        // modeset + external outputs + backlight. The BAR0 region
        // map is admitted (Gen11 shares Gen12's partitioning)
        // and the part is explicitly pre-GMD; display, external
        // display and backlight are admitted (fixture-validated,
        // silicon untested). The HPD/session layer still fails
        // closed for Gen11 (its own Gen12 gates), so this flip
        // arms no session path.
        if !Generation::IceLake.display_supported()
            || !Generation::IceLake.external_display_supported()
            || !Generation::IceLake.backlight_supported()
            || Generation::IceLake.region_generation() != Some(RegionGeneration::Gen11)
            || Generation::IceLake.has_gmd_id()
            || !Generation::TigerLake.has_gmd_id()
        {
            return TestResult::Fail(
                "Gen11 must admit regions + display + external + backlight while GMD stays gated",
            );
        }
        if !Generation::TigerLake.external_display_supported()
            || !Generation::AlderLake.external_display_supported()
            || !Generation::IceLake.external_display_supported()
            || !Generation::Skylake.external_display_supported()
            || Generation::MeteorLake.external_display_supported()
            || Generation::PantherLake.external_display_supported()
        {
            return TestResult::Fail("external display sequences must remain Gen12 + Gen11 + Gen9");
        }
        // Backlight stays Gen12 + Gen11 + Gen9 (Lane 8: SKL
        // drives the SPT PWM block, ICL shares the BXT-style
        // PWM block) until the composition lane (PR #1037)
        // lands the MTL PWM path.
        if !Generation::TigerLake.backlight_supported()
            || !Generation::AlderLake.backlight_supported()
            || !Generation::IceLake.backlight_supported()
            || !Generation::Skylake.backlight_supported()
            || Generation::MeteorLake.backlight_supported()
            || Generation::PantherLake.backlight_supported()
        {
            return TestResult::Fail("backlight gate must be Gen12 + Gen11 + Gen9 pending #1037");
        }
        // Region generations follow the same split, with Lunar
        // Lake on the Xe2-LPD table (display 20) and Panther Lake
        // on the Xe3-LPD table (display 30) — separate tables
        // sharing the Xe-LPG BAR0 layout.
        if Generation::MeteorLake.region_generation() != Some(RegionGeneration::XeLpg)
            || Generation::LunarLake.region_generation() != Some(RegionGeneration::Xe2Lpd)
            || Generation::PantherLake.region_generation() != Some(RegionGeneration::Xe3Lpd)
        {
            return TestResult::Fail("region generation map wrong for MTL/LNL/PTL");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu", smoke_display_generation_gates);

    fn smoke_unsupported_external_hpd_never_touches_mmio() -> TestResult {
        struct NoAccess;
        impl crate::intel_gpu_aux::MmioWindow for NoAccess {
            fn read32(&self, _: u64) -> u32 {
                panic!("unsupported HPD generation read MMIO")
            }
            fn write32(&self, _: u64, _: u32) {
                panic!("unsupported HPD generation wrote MMIO")
            }
        }
        for generation in [Generation::MeteorLake, Generation::PantherLake] {
            enable_external_hpd(&NoAccess, generation);
            if poll_external_hpd(&NoAccess, generation).is_some() {
                return TestResult::Fail("unsupported HPD generation must report no events");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu",
        smoke_unsupported_external_hpd_never_touches_mmio
    );

    /// Arrow Lake classification (#1023): the product name says
    /// "new generation", the silicon says Xe-LPG. Linux binds
    /// every ARL ID to the Meteor Lake device info / display
    /// descriptor (i915 `INTEL_ARL_IDS(..., &mtl_info)`, xe and
    /// display `&mtl_desc`), so the rows classify
    /// `Generation::MeteorLake` under `asic: "arrowlake"` — the
    /// Raptor-Lake-under-AlderLake pattern. This fixture pins
    /// the whole set (including B640, which the pci.ids v2.2
    /// extract lane 1 worked from did not carry, though the
    /// i915 ID macros and current pci.ids do) so a future
    /// "helpful" reclassification to a distinct generation — or
    /// worse, to Gen12, which would arm the Gen12 modeset
    /// against Xe-LPG silicon — fails here first.
    fn smoke_arrowlake_classification() -> TestResult {
        const ARL_DIDS: &[u16] = &[ARL_7D41, ARL_7D51, ARL_7D67, ARL_7DD1, ARL_B640];
        for did in ARL_DIDS {
            let info = match chip_info_for_pci_id(INTEL_VENDOR, *did) {
                Some(i) => i,
                None => return TestResult::Fail("Arrow Lake DID does not classify"),
            };
            if info.asic != "arrowlake" {
                return TestResult::Fail("Arrow Lake DID classifies to the wrong ASIC");
            }
            if info.generation != Generation::MeteorLake {
                return TestResult::Fail("Arrow Lake must classify as MeteorLake (Xe-LPG)");
            }
            // Disposition follows the Meteor Lake rows exactly:
            // since #1016 that is the Xe-LPG display sequence and
            // region map — never the Gen12 one.
            if !info.generation.display_supported() {
                return TestResult::Fail("Arrow Lake must arm the Xe-LPG display (#1016)");
            }
            if info.generation.region_generation() != Some(RegionGeneration::XeLpg) {
                return TestResult::Fail("Arrow Lake must claim the Xe-LPG region map");
            }
        }
        // No bleed across the shared 0x7Dxx space: the sibling
        // Meteor Lake IDs keep their own ASIC name.
        for did in [MTL_7D40, MTL_7D45, MTL_7D55, MTL_7D60, MTL_7DD5] {
            match chip_info_for_pci_id(INTEL_VENDOR, did) {
                Some(i) if i.asic == "meteorlake" && i.generation == Generation::MeteorLake => {}
                _ => return TestResult::Fail("Meteor Lake DID misclassified next to Arrow Lake"),
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu", smoke_arrowlake_classification);

    /// Gen11 classification (Lane 1): all 26 IDs from Linux
    /// `INTEL_ICL_IDS` / `INTEL_EHL_IDS` / `INTEL_JSL_IDS`
    /// classify as `Generation::IceLake` under their product
    /// ASIC, resolve to the Gen11 GT sub-platform with its GuC
    /// firmware family, and carry the post-Lane-5/8
    /// disposition (display, external display and backlight
    /// armed). This pins the whole set so a future
    /// reclassification — or arming the Gen12 modeset against
    /// Gen11 silicon — fails here first.
    fn smoke_icelake_classification() -> TestResult {
        use crate::intel_gpu_gt::{Gen11Platform, GtPlatform};
        const ICL_DIDS: &[u16] = &[
            ICL_8A50, ICL_8A51, ICL_8A52, ICL_8A53, ICL_8A54, ICL_8A56, ICL_8A57, ICL_8A58,
            ICL_8A59, ICL_8A5A, ICL_8A5B, ICL_8A5C, ICL_8A5D, ICL_8A70, ICL_8A71,
        ];
        const EHL_DIDS: &[u16] = &[EHL_4541, EHL_4551, EHL_4555, EHL_4557, EHL_4570, EHL_4571];
        const JSL_DIDS: &[u16] = &[JSL_4E51, JSL_4E55, JSL_4E57, JSL_4E61, JSL_4E71];
        for (dids, asic, platform, firmware) in [
            (
                ICL_DIDS,
                "icelake",
                GtPlatform::Gen11(Gen11Platform::IceLake),
                "i915/icl_guc_70.1.1.bin",
            ),
            (
                EHL_DIDS,
                "elkhartlake",
                GtPlatform::Gen11(Gen11Platform::ElkhartLake),
                "i915/ehl_guc_70.1.1.bin",
            ),
            (
                JSL_DIDS,
                "jasperlake",
                GtPlatform::Gen11(Gen11Platform::JasperLake),
                "i915/ehl_guc_70.1.1.bin",
            ),
        ] {
            for did in dids {
                let info = match chip_info_for_pci_id(INTEL_VENDOR, *did) {
                    Some(i) => i,
                    None => return TestResult::Fail("Gen11 DID does not classify"),
                };
                if info.asic != asic {
                    return TestResult::Fail("Gen11 DID classifies to the wrong ASIC");
                }
                if info.generation != Generation::IceLake {
                    return TestResult::Fail("Gen11 DID must classify as IceLake");
                }
                if GtPlatform::from_pci(INTEL_VENDOR, *did) != Some(platform) {
                    return TestResult::Fail("Gen11 DID resolves to the wrong GT platform");
                }
                match platform.guc() {
                    Some(profile)
                        if profile.firmware == firmware
                            && profile.minimum_version == (70, 1, 1) => {}
                    _ => return TestResult::Fail("Gen11 DID has the wrong GuC profile"),
                }
                // Post-Lane-5/8 disposition: display armed by
                // Lane 5 (internal panel), external display and
                // backlight armed by Lane 8, region map admitted,
                // pre-GMD presence.
                if !info.generation.display_supported()
                    || !info.generation.external_display_supported()
                    || !info.generation.backlight_supported()
                    || info.generation.region_generation() != Some(RegionGeneration::Gen11)
                    || info.generation.has_gmd_id()
                {
                    return TestResult::Fail("Gen11 disposition wrong after Lane 8");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu", smoke_icelake_classification);

    /// Gen9 classification (Lane 1): all 86 IDs from Linux
    /// `INTEL_SKL_IDS` (25) / `INTEL_KBL_IDS` (22) /
    /// `INTEL_CFL_IDS` (17) / `INTEL_WHL_IDS` (5) /
    /// `INTEL_CML_IDS` (17) — each row re-verified against
    /// `include/drm/intel/pciids.h` (Linux 7.4-rc2) at authoring
    /// time — classify as `Generation::Skylake` under their
    /// product ASIC, resolve to the Gen9 GT sub-platform with
    /// its GuC firmware family, and carry the Lane-1
    /// disposition (regions admitted, pre-GMD presence,
    /// display / external display / backlight gated). This
    /// pins the whole set so a future reclassification — or
    /// arming the Gen12 modeset against Gen9 silicon — fails
    /// here first.
    fn smoke_skylake_classification() -> TestResult {
        use crate::intel_gpu_gt::{Gen9Platform, GtPlatform};
        const SKL_DIDS: &[u16] = &[
            SKL_1902, SKL_1906, SKL_190A, SKL_190B, SKL_190E, SKL_1912, SKL_1913, SKL_1915,
            SKL_1916, SKL_1917, SKL_191A, SKL_191B, SKL_191D, SKL_191E, SKL_1921, SKL_1923,
            SKL_1926, SKL_1927, SKL_192A, SKL_192B, SKL_192D, SKL_1932, SKL_193A, SKL_193B,
            SKL_193D,
        ];
        const KBL_DIDS: &[u16] = &[
            KBL_5902, KBL_5906, KBL_5908, KBL_590A, KBL_590B, KBL_590E, KBL_5912, KBL_5913,
            KBL_5915, KBL_5916, KBL_5917, KBL_591A, KBL_591B, KBL_591C, KBL_591D, KBL_591E,
            KBL_5921, KBL_5923, KBL_5926, KBL_5927, KBL_593B, KBL_87C0,
        ];
        const CFL_DIDS: &[u16] = &[
            CFL_3E90, CFL_3E91, CFL_3E92, CFL_3E93, CFL_3E94, CFL_3E96, CFL_3E98, CFL_3E99,
            CFL_3E9A, CFL_3E9B, CFL_3E9C, CFL_3EA5, CFL_3EA6, CFL_3EA7, CFL_3EA8, CFL_3EA9,
            CFL_87CA,
        ];
        const WHL_DIDS: &[u16] = &[WHL_3EA0, WHL_3EA1, WHL_3EA2, WHL_3EA3, WHL_3EA4];
        const CML_DIDS: &[u16] = &[
            CML_9B21, CML_9B41, CML_9BA2, CML_9BA4, CML_9BA5, CML_9BA8, CML_9BAA, CML_9BAC,
            CML_9BC2, CML_9BC4, CML_9BC5, CML_9BC6, CML_9BC8, CML_9BCA, CML_9BCC, CML_9BE6,
            CML_9BF6,
        ];
        for (dids, asic, platform, firmware) in [
            (
                SKL_DIDS,
                "skylake",
                GtPlatform::Gen9(Gen9Platform::Skylake),
                "i915/skl_guc_70.1.1.bin",
            ),
            (
                KBL_DIDS,
                "kabylake",
                GtPlatform::Gen9(Gen9Platform::KabyLake),
                "i915/kbl_guc_70.1.1.bin",
            ),
            (
                CFL_DIDS,
                "coffeelake",
                GtPlatform::Gen9(Gen9Platform::KabyLake),
                "i915/kbl_guc_70.1.1.bin",
            ),
            (
                WHL_DIDS,
                "whiskeylake",
                GtPlatform::Gen9(Gen9Platform::KabyLake),
                "i915/kbl_guc_70.1.1.bin",
            ),
            (
                CML_DIDS,
                "cometlake",
                GtPlatform::Gen9(Gen9Platform::CometLake),
                "i915/kbl_guc_70.1.1.bin",
            ),
        ] {
            for did in dids {
                let info = match chip_info_for_pci_id(INTEL_VENDOR, *did) {
                    Some(i) => i,
                    None => return TestResult::Fail("Gen9 DID does not classify"),
                };
                if info.asic != asic {
                    return TestResult::Fail("Gen9 DID classifies to the wrong ASIC");
                }
                if info.generation != Generation::Skylake {
                    return TestResult::Fail("Gen9 DID must classify as Skylake");
                }
                if GtPlatform::from_pci(INTEL_VENDOR, *did) != Some(platform) {
                    return TestResult::Fail("Gen9 DID resolves to the wrong GT platform");
                }
                match platform.guc() {
                    Some(profile)
                        if profile.firmware == firmware
                            && profile.minimum_version == (70, 1, 1) => {}
                    _ => return TestResult::Fail("Gen9 DID has the wrong GuC profile"),
                }
                // Lane-8 disposition: regions admitted, pre-GMD
                // presence, display / external display /
                // backlight all admitted (Lanes 5 and 8 flipped
                // those).
                if !info.generation.display_supported()
                    || !info.generation.external_display_supported()
                    || !info.generation.backlight_supported()
                    || info.generation.region_generation() != Some(RegionGeneration::Gen9)
                    || info.generation.has_gmd_id()
                {
                    return TestResult::Fail("Gen9 disposition wrong after Lane 8");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu", smoke_skylake_classification);

    /// Generation-aware Stage-1 presence (`stage1_presence`):
    /// the Gen12 GMD path is unchanged, and the Gen11 path
    /// refuses only on an all-ones config-space re-read — the
    /// ungrounded MMIO pair cannot refuse a Gen11 part.
    fn smoke_stage1_presence_generation_aware() -> TestResult {
        // Gen12: a live GMD_ID + TRBLK pair passes; either
        // all-ones refuses; a missing pair refuses.
        if stage1_presence(
            Generation::TigerLake,
            Some((0x0001_2000, 0x0000_0001)),
            0x9A49_8086,
        ) != Ok(Some(0x0001_2000))
        {
            return TestResult::Fail("Gen12 live GMD pair must pass presence");
        }
        for gmd in [
            Some((0xFFFF_FFFF, 0x0000_0001)),
            Some((0x0001_2000, 0xFFFF_FFFF)),
            Some((0xFFFF_FFFF, 0xFFFF_FFFF)),
            None,
        ] {
            if stage1_presence(Generation::TigerLake, gmd, 0x9A49_8086)
                != Err(IntelGpuError::DeviceGone)
            {
                return TestResult::Fail("Gen12 gone device must fail presence");
            }
        }
        // Gen11: a live config-space dword passes with no GMD_ID;
        // all-ones config refuses.
        if stage1_presence(Generation::IceLake, None, 0x8A50_8086) != Ok(None) {
            return TestResult::Fail("Gen11 live config re-read must pass presence");
        }
        if stage1_presence(Generation::IceLake, None, 0xFFFF_FFFF) != Err(IntelGpuError::DeviceGone)
        {
            return TestResult::Fail("Gen11 gone device must fail presence");
        }
        // The MMIO pair is ignored on Gen11 even when it reads
        // all-ones — those offsets predate GMD_ID.
        if stage1_presence(
            Generation::IceLake,
            Some((0xFFFF_FFFF, 0xFFFF_FFFF)),
            0x8A50_8086,
        ) != Ok(None)
        {
            return TestResult::Fail("Gen11 MMIO pair must not refuse presence");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu",
        smoke_stage1_presence_generation_aware
    );

    fn smoke_mtl_external_hook_pass_allocates_publishes_and_withdraws() -> TestResult {
        // Drives the production hook core (`mtl_external_pass`) over the
        // native MTL route model with the real process-wide service and
        // hotplug owners. Allocation and publication are recorded instead of
        // touching a real GGTT or the fb-console observer.
        extern crate alloc;
        use crate::intel_gpu_aux::MmioWindow as _;
        use crate::intel_gpu_xelpg::XeLpgPort;
        use crate::intel_gpu_xelpg_external::tests::{edid_for, ExtFake, Sink};
        use crate::intel_gpu_xelpg_hpd::{port_hotplug_ctl, DP_ALT_HPD_LONG_DETECT};
        use alloc::vec::Vec;
        const BAR: u64 = 0xF00D_0000_0000;
        let io = ExtFake::new(
            XeLpgPort::Tc1,
            Sink::new(0x14, edid_for(65_000, 1024, 320, 24, 136, 768, 38, 3, 6)),
        );
        // Fresh process-wide owners; a fresh teardown touches nothing.
        if !crate::intel_gpu_xelpg_external::teardown_mtl_external(&io, Generation::MeteorLake)
            || MTL_PUBLISHED.load(core::sync::atomic::Ordering::Acquire) != 0
        {
            return TestResult::Fail("hook test needs fresh MTL owners");
        }
        let mut events = 0u32;
        let mut afters = 0u32;
        let sizes: core::cell::RefCell<Vec<u64>> = core::cell::RefCell::new(Vec::new());
        // Lock-free readers sampled mid-pass (the service is held): no
        // route yet, so "stopped" without a transient, while DC re-entry
        // stays refused for the contended pass.
        let mid_pass: core::cell::RefCell<Vec<(bool, bool)>> = core::cell::RefCell::new(Vec::new());
        let mut published: Vec<MtlPublication> = Vec::new();
        let mut alloc = |_window: crate::intel_gpu_pipes::Pipe, size: u64| {
            sizes.borrow_mut().push(size);
            mid_pass.borrow_mut().push((
                crate::intel_gpu_xelpg_external::routes_stopped(),
                crate::intel_gpu_xelpg_external::external_route_blocks_dc(),
            ));
            Some(ScanoutAllocation {
                gtt_offset: 0x100_0000,
                phys_base: 0x7_0000_0000,
                order: 10,
                size_bytes: size,
            })
        };
        // Gen12 never reaches the MTL owners.
        if mtl_external_pass(
            &io,
            Generation::TigerLake,
            BAR,
            &crate::intel_gpu_xelpg_external::MtlDisplay::NONE,
            &mut || events += 1,
            &mut || afters += 1,
            &mut alloc,
            &mut |p| published.push(p),
        ) || events != 0
            || !io.writes.borrow().is_empty()
        {
            return TestResult::Fail("non-MTL pass must not touch the MTL owners");
        }
        // Plugged DP-alt sink: one event, one allocation, one publication.
        let handled = mtl_external_pass(
            &io,
            Generation::MeteorLake,
            BAR,
            &crate::intel_gpu_xelpg_external::MtlDisplay::NONE,
            &mut || events += 1,
            &mut || afters += 1,
            &mut alloc,
            &mut |p| published.push(p),
        );
        // The image is reported on Pipe B: with Pipe A dark the route still
        // never takes it (it stays the internal panel's).
        let first = match published.as_slice() {
            [MtlPublication::Publish(fb, serial, crate::intel_gpu_pipes::Pipe::B)] => {
                (*fb, *serial)
            }
            _ => return TestResult::Fail("activation must publish exactly one Pipe B image"),
        };
        if *mid_pass.borrow() != [(true, true)] {
            return TestResult::Fail("mid-pass readers must see stopped and DC blocked");
        }
        if !handled
            || events != 1
            || afters != 1
            || *sizes.borrow() != [scanout_size_bytes(1024, 768)]
            || first.0.addr != 0x7_0000_0000
            || first.0.width != 1024
            || first.0.height != 768
            || first.0.pitch != padded_stride_bytes(1024)
            || MTL_PUBLISHED.load(core::sync::atomic::Ordering::Acquire) != first.1
            || crate::intel_gpu_xelpg_external::routes_stopped()
        {
            return TestResult::Fail("connect pass must allocate, activate and publish");
        }
        // No pending event: no work, no suspension.
        if mtl_external_pass(
            &io,
            Generation::MeteorLake,
            BAR,
            &crate::intel_gpu_xelpg_external::MtlDisplay::NONE,
            &mut || events += 1,
            &mut || afters += 1,
            &mut alloc,
            &mut |p| published.push(p),
        ) || events != 1
            || afters != 1
        {
            return TestResult::Fail("idle pass must not report work");
        }
        // Unplug: the route is withdrawn and exactly its serial is withdrawn.
        io.pica_isr.set(0);
        io.phy.write32(
            port_hotplug_ctl(0),
            io.phy.read32(port_hotplug_ctl(0)) | DP_ALT_HPD_LONG_DETECT,
        );
        published.clear();
        let handled = mtl_external_pass(
            &io,
            Generation::MeteorLake,
            BAR,
            &crate::intel_gpu_xelpg_external::MtlDisplay::NONE,
            &mut || events += 1,
            &mut || afters += 1,
            &mut alloc,
            &mut |p| published.push(p),
        );
        if !handled
            || !matches!(published.as_slice(), [MtlPublication::Withdraw(s)] if *s == first.1)
            || MTL_PUBLISHED.load(core::sync::atomic::Ordering::Acquire) != 0
            || !crate::intel_gpu_xelpg_external::routes_stopped()
        {
            return TestResult::Fail("unplug must withdraw the exact published serial");
        }
        // Replug: the retained allocation is reused; a new serial publishes.
        io.pica_isr
            .set(crate::intel_gpu_xelpg_hpd::pica_dp_alt_hotplug(0));
        io.phy.write32(
            port_hotplug_ctl(0),
            io.phy.read32(port_hotplug_ctl(0)) | DP_ALT_HPD_LONG_DETECT,
        );
        published.clear();
        let _ = mtl_external_pass(
            &io,
            Generation::MeteorLake,
            BAR,
            &crate::intel_gpu_xelpg_external::MtlDisplay::NONE,
            &mut || events += 1,
            &mut || afters += 1,
            &mut alloc,
            &mut |p| published.push(p),
        );
        let reused = sizes.borrow().len() == 1
            && matches!(published.as_slice(), [MtlPublication::Publish(fb, s, _)]
                if fb.addr == 0x7_0000_0000 && *s != first.1);
        // Leave the process-wide owners and the retained slot fresh.
        let torn =
            crate::intel_gpu_xelpg_external::teardown_mtl_external(&io, Generation::MeteorLake);
        MTL_PUBLISHED.store(0, core::sync::atomic::Ordering::Release);
        {
            let mut slot = MTL_SCANOUT.lock();
            if slot.is_some_and(|(owner, _)| owner == BAR) {
                *slot = None;
            }
        }
        if !reused || !torn || !crate::intel_gpu_xelpg_external::routes_stopped() {
            return TestResult::Fail("replug must reuse the allocation; teardown must complete");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu",
        smoke_mtl_external_hook_pass_allocates_publishes_and_withdraws
    );

    fn smoke_mtl_external_hook_pass_publishes_and_retires_hdmi_route() -> TestResult {
        // The process-wide service under the no-VBT policy picks HDMI on
        // DDI B when no DPCD answers; the hook publishes it like a DP
        // route, and the suspend/reset teardown retires it.
        extern crate alloc;
        use crate::intel_gpu_aux::MmioWindow as _;
        use crate::intel_gpu_xelpg_external::tests::{edid_for, hdmi_on_ddi_b};
        use alloc::vec::Vec;
        const BAR: u64 = 0xF00D_1000_0000;
        let io = hdmi_on_ddi_b(edid_for(65_000, 1024, 320, 24, 136, 768, 38, 3, 6));
        if !crate::intel_gpu_xelpg_external::teardown_mtl_external(&io, Generation::MeteorLake)
            || MTL_PUBLISHED.load(core::sync::atomic::Ordering::Acquire) != 0
        {
            return TestResult::Fail("HDMI hook test needs fresh MTL owners");
        }
        let mut published: Vec<MtlPublication> = Vec::new();
        let mut alloc = |_window: crate::intel_gpu_pipes::Pipe, size: u64| {
            Some(ScanoutAllocation {
                gtt_offset: 0x100_0000,
                phys_base: 0x7_1000_0000,
                order: 10,
                size_bytes: size,
            })
        };
        let handled = mtl_external_pass(
            &io,
            Generation::MeteorLake,
            BAR,
            &crate::intel_gpu_xelpg_external::MtlDisplay::NONE,
            &mut || {},
            &mut || {},
            &mut alloc,
            &mut |p| published.push(p),
        );
        let serial = match published.as_slice() {
            [MtlPublication::Publish(fb, serial, crate::intel_gpu_pipes::Pipe::B)]
                if fb.addr == 0x7_1000_0000 && fb.width == 1024 && fb.height == 768 =>
            {
                *serial
            }
            _ => return TestResult::Fail("HDMI activation must publish exactly one Pipe B image"),
        };
        if !handled
            || !crate::intel_gpu_xelpg_external::route_live()
            || MTL_PUBLISHED.load(core::sync::atomic::Ordering::Acquire) != serial
        {
            return TestResult::Fail("HDMI route must be live and published");
        }
        // Suspend/GT-reset retirement: the route stops and releases, so the
        // publication the glue withdraws is exactly this serial.
        let torn =
            crate::intel_gpu_xelpg_external::teardown_mtl_external(&io, Generation::MeteorLake);
        let published = MTL_PUBLISHED.swap(0, core::sync::atomic::Ordering::AcqRel);
        let withdrawn = !crate::intel_gpu_xelpg_external::route_live() && published == serial;
        {
            let mut slot = MTL_SCANOUT.lock();
            if slot.is_some_and(|(owner, _)| owner == BAR) {
                *slot = None;
            }
        }
        if !torn
            || !withdrawn
            || !crate::intel_gpu_xelpg_external::routes_stopped()
            || io.read32(crate::intel_gpu_xelpg::XeLpgPort::B.ddi_buf_ctl()) & (1 << 31) != 0
        {
            return TestResult::Fail("teardown must stop DDI B and leave the serial withdrawable");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu",
        smoke_mtl_external_hook_pass_publishes_and_retires_hdmi_route
    );

    /// Every concurrently lit MTL external surface gets its own console
    /// GGTT window: an MST route's streams in slot 0 take Pipe B, C and D's
    /// (`alloc_contiguous_scanout_with_format` maps at the window's offset,
    /// so a shared window would remap the earlier stream's pages), and a
    /// second concurrent route takes Pipe C's, which MST never shares with
    /// it (MST is refused beside a sibling route).
    fn smoke_mtl_external_streams_take_distinct_ggtt_windows() -> TestResult {
        use crate::intel_gpu_multipipe::scanout_gtt_offset;
        use crate::intel_gpu_pipes::Pipe;
        let windows: alloc::vec::Vec<_> = (0..4).map(|s| mtl_scanout_window(0, s)).collect();
        if windows != [Some(Pipe::B), Some(Pipe::C), Some(Pipe::D), None]
            || mtl_scanout_window(1, 0) != Some(Pipe::C)
            || mtl_scanout_window(1, 1).is_some()
        {
            return TestResult::Fail("streams must take Pipe B, C, D windows; slot 1 Pipe C");
        }
        // 16 MiB + 32 MiB per pipe: B, C, D at 48, 80 and 112 MiB, each a
        // whole 32 MiB console window below the GEM scanout arena (160 MiB).
        let offsets: alloc::vec::Vec<u64> = [Pipe::B, Pipe::C, Pipe::D]
            .into_iter()
            .map(scanout_gtt_offset)
            .collect();
        if offsets != [48 << 20, 80 << 20, 112 << 20]
            || offsets
                .iter()
                .any(|o| o + crate::intel_gpu_gtt::CONSOLE_SCANOUT_WINDOW_BYTES > 160 << 20)
        {
            return TestResult::Fail("each window must be its own 32 MiB console range");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu",
        smoke_mtl_external_streams_take_distinct_ggtt_windows
    );
}
