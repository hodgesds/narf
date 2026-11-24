//! Intel iGPU bridge — wires DP Alt Mode → Intel display engine.
//!
//! Implements [`DpAltModeGpuBridge`] for the Intel iGPU driver. The
//! bridge sits between the USB-C side (which has just finished the
//! VESA DP-Alt VDM dance) and the display engine (Pipe / Transcoder /
//! DDI). Per VESA DP Alt Mode v2.0 §6 and Tiger Lake / Alder Lake
//! PRM Vol. 12 §"DDI Buffer", the source side does:
//!
//! 1. Map USB-C connector → DDI (TC1..TC6 → Ddi::D..I on Gen12,
//!    TC1..TC4 → Ddi::C..F on Ice Lake).
//! 2. Bind a Pipe + Transcoder to that DDI.
//! 3. Open an AUX channel — DPCD reads now flow over the USB-C aux
//!    pins. EDID over I²C-over-AUX gives the sink's preferred mode.
//! 4. Run a modeset using the existing [`Modeset`] orchestrator.
//!
//! ## Scope
//!
//! - **Owned by this file**: USB-C → DDI mapping, MMIO window
//!   adapter for the BAR0 `MmioRegion`, dispatch into AUX + Modeset.
//! - A session retains its pipe, scanout and TC-cold/AUX/PHY ownership.
//!   Detach stops the pipe, DDI transport and Dekel PLL before release;
//!   uncertain stop retains the session, published image and backing, and
//!   vetoes display power retirement. Successful modeset publication carries
//!   a unique session serial, so stale detach cannot withdraw a newer output.
//! - Tiger Lake and Alder Lake-P/N use their own banked Dekel PLL, clock
//!   routing and TX presets. Negotiation respects the PD lane limit and
//!   source training patterns/levels track the shared sink algorithm.
//! - Ice Lake drives its MG PHYs: the FIA ownership handshake
//!   (`icl_tc_phy_connect`), the MG PLL and levels through the Gen11
//!   modeset, and the handshake's release on detach.
//!
//! ## USB-C connector → DDI mapping
//!
//! This bridge exposes TC1..TC6 as DDIs D..I and requires native TC
//! numbering from its TCPM connector registration. Tiger Lake has all six;
//! Alder Lake-P/N have four and their typed Dekel owner rejects TC5/TC6 before
//! MMIO. A successful PD negotiation alone does not establish
//! board wiring. Arbitrary firmware/UCSI connector numbering needs a
//! board routing map before it can use this bridge.

extern crate alloc;

use alloc::sync::Arc;
use core::fmt;

use narf_driver_runtime::MmioRegion;
use narf_drivers_usbpd::dp_gpu_bridge::{
    self, ConnectorId, DpAltModeGpuBridge, DpBridgeError, DpLinkConfig,
};

use narf_lib::sync::IrqSafeSpinLock;

use crate::dp_edid::read_panel_edid;
use crate::intel_gpu;
use crate::intel_gpu_aux::{IntelAux, MmioWindow, SourceFamily};
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_gen11_mg_phy::{MgPort, TcMode};
use crate::intel_gpu_gen12_tc::DklPort;
use crate::intel_gpu_gtt::ContiguousScanout;
use crate::intel_gpu_modeset::{Framebuffer, Mode, Modeset, ModesetError, PixelFormat};
use crate::intel_gpu_multipipe::{self, PipeOwner, PipeUse};
use crate::intel_gpu_pipes::Pipe;

/// The Type-C PHY a session owns: Gen12's Dekel port or Ice Lake's MG port.
#[derive(Copy, Clone, Debug)]
enum BridgePort {
    Dekel(DklPort),
    Mg(MgPort),
}

#[derive(Copy, Clone, Debug)]
struct BridgeSession {
    port: BridgePort,
    bar: u64,
    pipe: Option<Pipe>,
    publication_serial: u64,
}
static SESSIONS: narf_lib::mutex::Mutex<[Option<BridgeSession>; 9]> =
    narf_lib::mutex::Mutex::new([None; 9]);

/// System/display power transitions must not retire a function behind an
/// attached or quarantined Type-C owner. A racing attach also vetoes.
pub(crate) fn sessions_stopped(bar: u64) -> bool {
    SESSIONS
        .try_lock()
        .is_some_and(|sessions| sessions.iter().flatten().all(|session| session.bar != bar))
}

/// Map a USB-C [`ConnectorId`] to the Gen12 Type-C DDI it's wired
/// to. Returns `None` if the index is outside the documented TC1..6
/// range exposed by this bridge. DklPort separately checks the family's
/// physical TC count.
///
/// PRM Vol. 12 §"Display DDI Port Index":
///   TC1 = Ddi::D through TC6 = Ddi::I.
pub fn connector_to_ddi(connector: ConnectorId) -> Option<Ddi> {
    match connector.as_u32() {
        0 => Some(Ddi::D),
        1 => Some(Ddi::E),
        2 => Some(Ddi::F),
        3 => Some(Ddi::G),
        4 => Some(Ddi::H),
        5 => Some(Ddi::I),
        _ => None,
    }
}

/// [`connector_to_ddi`] for `family`: Gen12's TC1..TC6 → D..I, Ice Lake's
/// TC1..TC4 → C..F (`icl_display`: PORT_C..PORT_F are TC_PORT_1..4). Other
/// sources have no Type-C ports for this bridge.
pub fn connector_to_ddi_for(family: SourceFamily, connector: ConnectorId) -> Option<Ddi> {
    match family {
        SourceFamily::Gen12(_) => connector_to_ddi(connector),
        SourceFamily::Gen11(crate::intel_gpu_gt::Gen11Platform::IceLake) => {
            match connector.as_u32() {
                0 => Some(Ddi::C),
                1 => Some(Ddi::D),
                2 => Some(Ddi::E),
                3 => Some(Ddi::F),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The source this bridge drives on `chip`: a Gen12 family, or Ice Lake.
fn bridge_family(chip: crate::intel_gpu::ChipInfo) -> Option<SourceFamily> {
    if let Some(family) = crate::intel_gpu_modeset::gen12_family_for_chip(chip) {
        return Some(SourceFamily::Gen12(family));
    }
    match crate::intel_gpu_gt::GtPlatform::from_pci(chip.vid, chip.did) {
        Some(crate::intel_gpu_gt::GtPlatform::Gen11(
            platform @ crate::intel_gpu_gt::Gen11Platform::IceLake,
        )) => Some(SourceFamily::Gen11(platform)),
        _ => None,
    }
}

/// The ddi a probed controller maps `connector` to.
fn probed_ddi(connector: ConnectorId) -> Option<Ddi> {
    intel_gpu::with_display_info(|gpu| bridge_family(gpu.chip))
        .flatten()
        .and_then(|family| connector_to_ddi_for(family, connector))
}

// ── MMIO adapter ─────────────────────────────────────────────────

/// Adapter that lets [`IntelAux`] / [`Modeset`] (which want an
/// `MmioWindow`) drive an `MmioRegion`. The wrapper is a zero-cost
/// borrow — `MmioRegion::read32` / `write32` are `unsafe` because
/// the caller is asserting the BAR is mapped + identity-typed; the
/// safety contract is documented on `IntelGpu::bring_up` and held
/// for the whole driver lifetime.
struct MmioRegionWindow<'a> {
    region: &'a MmioRegion,
    family: SourceFamily,
    /// Tiger Lake UY (GT2) part, from the owning chip's PCI
    /// device ID — carried so a `Modeset` built over this
    /// window selects the UY HBR2 table on combo DDIs (the
    /// Type-C DDIs this bridge drives use the DKL PHY, where
    /// the flag is inert, but the window still reports the
    /// real value).
    tgl_uy: bool,
}

impl<'a> MmioRegionWindow<'a> {
    fn new(region: &'a MmioRegion, family: SourceFamily, tgl_uy: bool) -> Self {
        Self {
            region,
            family,
            tgl_uy,
        }
    }
}

impl<'a> MmioWindow for MmioRegionWindow<'a> {
    fn gen12_display_family(&self) -> Option<crate::intel_gpu_gt::Gen12Platform> {
        self.family.gen12()
    }
    fn gen11_display_platform(&self) -> Option<crate::intel_gpu_gt::Gen11Platform> {
        match self.family {
            SourceFamily::Gen11(platform) => Some(platform),
            _ => None,
        }
    }
    fn tgl_uy(&self) -> bool {
        self.tgl_uy
    }
    fn read32(&self, off: u64) -> u32 {
        // SAFETY: BAR0 is mapped for the lifetime of `IntelGpu`.
        unsafe { self.region.read32(off) }
    }
    fn write32(&self, off: u64, val: u32) {
        // SAFETY: BAR0 is mapped for the lifetime of `IntelGpu`.
        unsafe { self.region.write32(off, val) }
    }
}

// ── Bridge impl ──────────────────────────────────────────────────

/// Intel iGPU bridge. Stateless — pulls the live `IntelGpu` handle
/// from the global controller slot on each call.
#[derive(Debug, Default)]
pub struct IntelDpBridge;

impl IntelDpBridge {
    pub const fn new() -> Self {
        IntelDpBridge
    }
}

impl DpAltModeGpuBridge for IntelDpBridge {
    fn name(&self) -> &'static str {
        "intel-gpu"
    }

    fn enter_dp_mode(&self, cfg: &DpLinkConfig) -> Result<(), DpBridgeError> {
        // Need a live Intel iGPU controller. If we're on a non-Intel
        // platform, defer to the next bridge in the registry by
        // signalling "no connector here".
        if !intel_gpu::is_probed() {
            return Err(DpBridgeError::NoSuchConnector);
        }
        // Resolve the DDI for this USB-C connector on the probed source.
        // If the index doesn't fit its Type-C mapping, pass — another
        // bridge (amdgpu / nvidia) might own this connector.
        let Some(ddi) = probed_ddi(cfg.connector) else {
            return Err(DpBridgeError::NoSuchConnector);
        };

        let display =
            intel_gpu::with_controller(|gpu| crate::intel_gpu_kms::display_for_bar(&gpu.gtt_mmadr))
                .flatten();
        let mut ownership = match display.as_ref() {
            Some(display) => Some(display.legacy().map_err(|_| DpBridgeError::NotReady)?),
            None => None,
        };
        if let Some(guard) = ownership.as_mut() {
            guard.suspend();
        }

        let mut outcome = Err(DpBridgeError::NotReady);
        intel_gpu::with_display_info(|gpu| {
            outcome = self.bind_and_modeset(gpu, ddi, cfg);
            if outcome.is_err() {
                let _ = stop_session(gpu, ddi);
            }
        });
        outcome
    }

    fn exit_dp_mode(&self, connector: ConnectorId) -> Result<(), DpBridgeError> {
        let Some(ddi) = probed_ddi(connector) else {
            return Ok(());
        };
        if SESSIONS.try_lock().ok_or(DpBridgeError::NotReady)?[ddi as usize].is_none() {
            return Ok(());
        }
        let display =
            intel_gpu::with_controller(|gpu| crate::intel_gpu_kms::display_for_bar(&gpu.gtt_mmadr))
                .flatten();
        let mut guard = match display.as_ref() {
            Some(display) => Some(display.legacy().map_err(|_| DpBridgeError::NotReady)?),
            None => None,
        };
        if let Some(guard) = guard.as_mut() {
            guard.suspend();
        }
        intel_gpu::with_display_info(|gpu| stop_session(gpu, ddi))
            .unwrap_or(Err(DpBridgeError::NotReady))
    }
}

impl IntelDpBridge {
    fn bind_and_modeset(
        &self,
        gpu: &intel_gpu::DisplayInfo,
        ddi: Ddi,
        cfg: &DpLinkConfig,
    ) -> Result<(), DpBridgeError> {
        if !gpu.chip.generation.external_display_supported() {
            return Err(DpBridgeError::NoSuchConnector);
        }
        let family = bridge_family(gpu.chip).ok_or(DpBridgeError::NoSuchConnector)?;
        let publication_serial =
            intel_gpu::next_external_scanout_serial().ok_or(DpBridgeError::NotReady)?;
        use core::fmt::Write as _;
        // Pre-GMD generations (Gen12, Ice Lake) have no GMD_ID; this is a
        // display-only path.
        let gmd = match gpu.gmd_id {
            Some(v) => alloc::format!("{v:#010x}"),
            None => alloc::string::String::from("none"),
        };
        let _ = writeln!(
            narf_console::Writer,
            "  intel-gpu/dp: DP-Alt active on {} (DDI {:?}, {} lanes, signaling=0x{:x}); \
             chip={} GMD_ID={}",
            cfg.connector,
            ddi,
            cfg.lanes,
            cfg.signaling,
            gpu.chip.asic,
            gmd,
        );

        let mmio = MmioRegionWindow::new(
            &gpu.gtt_mmadr,
            family,
            crate::intel_gpu_gen12_combo_phy::is_tgl_uy(gpu.chip.did),
        );
        if !matches!(cfg.lanes, 2 | 4) {
            return Err(DpBridgeError::ModesetFailed);
        }
        let port = match family {
            SourceFamily::Gen11(platform) => BridgePort::Mg(
                MgPort::new(ddi, platform).map_err(|_| DpBridgeError::NoSuchConnector)?,
            ),
            _ => BridgePort::Dekel(
                DklPort::new(&mmio, ddi).map_err(|_| DpBridgeError::NoSuchConnector)?,
            ),
        };
        {
            let mut sessions = SESSIONS.try_lock().ok_or(DpBridgeError::NotReady)?;
            if sessions[ddi as usize].is_some() {
                return Err(DpBridgeError::NotReady);
            }
            sessions[ddi as usize] = Some(BridgeSession {
                port,
                bar: gpu.gtt_mmadr.phys.raw(),
                pipe: None,
                publication_serial,
            });
        }
        // Ice Lake: claim the PHY from the FIA once its live state says
        // DP-alt (`icl_tc_phy_connect`); any lane count the pin assignment
        // carries is accepted here and bounded by the PD lanes below.
        let assigned_lanes = match port {
            BridgePort::Dekel(port) => port
                .acquire_dp_alt(&mmio, gpu.gtt_mmadr.phys.raw())
                .map_err(|_| DpBridgeError::NotReady)?,
            BridgePort::Mg(port) => port
                .connect(&mmio, TcMode::DpAlt, 1)
                .map_err(|_| DpBridgeError::NotReady)?,
        };
        let max_lanes = cfg.lanes.min(assigned_lanes);

        // Try an EDID readback over AUX. AUX may not yet be reachable
        // (DPRX side could still be waking up); a failure here isn't
        // fatal for the bridge contract — we just have no mode.
        let preferred_mode = read_preferred_mode_via_aux(&mmio, ddi);

        // Claim a pipe for this connector (#1017). claim_for is
        // keyed by DDI. The retained session rejects a concurrent
        // re-entry; successful detach releases its claim. No free pipe is a real
        // refusal: every pipe is scanning out something else.
        let owner = PipeOwner {
            ddi,
            used_for: PipeUse::AltModeBridge,
        };
        let Some(pipe) = intel_gpu_multipipe::claim_pipe_for(owner) else {
            let _ = writeln!(
                narf_console::Writer,
                "  intel-gpu/dp: no free pipe for DDI {:?} — all pipes owned",
                ddi,
            );
            return Err(DpBridgeError::NotReady);
        };
        SESSIONS.try_lock().ok_or(DpBridgeError::NotReady)?[ddi as usize]
            .as_mut()
            .ok_or(DpBridgeError::NotReady)?
            .pipe = Some(pipe);

        // A real scanout in the claimed pipe's GGTT window,
        // sized for the sink's preferred mode when known and
        // for 1920×1080 otherwise (the surface the modeset's
        // own EDID path most commonly lands on when the
        // bridge's read raced the sink's wake).
        let (width, height) = match preferred_mode {
            Some(m) => (m.h_active as u32, m.v_active as u32),
            None => (1920, 1080),
        };
        let stride_bytes = intel_gpu::padded_stride_bytes(width);
        let size_bytes = intel_gpu::scanout_size_bytes(width, height);
        let alloc = match crate::intel_gpu_gtt::alloc_contiguous_scanout_at(
            &gpu.gtt_mmadr,
            intel_gpu_multipipe::scanout_gtt_offset(pipe),
            size_bytes,
        ) {
            Ok(alloc) => alloc,
            Err(e) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  intel-gpu/dp: scanout allocation failed on DDI {:?}: {:?}",
                    ddi,
                    e,
                );
                return Err(DpBridgeError::ModesetFailed);
            }
        };
        retain_bridge_scanout(ddi, alloc);
        let fb = Framebuffer {
            phys_addr: alloc.gtt_offset as u64,
            stride_bytes,
            format: PixelFormat::Xrgb8888,
        };

        // Hand off to the modeset orchestrator, bound to the
        // claimed pipe. When the claim made this a multi-pipe
        // machine, the pipe gets its DBUF share and the pipes
        // already live are reprogrammed to theirs.
        let mut modeset = Modeset::for_pipe(&mmio, ddi, pipe);
        modeset.set_source_family(family);
        modeset.set_typec_width(max_lanes);
        let active = intel_gpu_multipipe::active_pipes();
        if active.len() >= 2 {
            if let Some((start, end)) = intel_gpu_multipipe::share_for(&mmio, &active, pipe) {
                modeset.set_dbuf_share(start, end);
                modeset.set_shared_cdclk(true);
            }
        }
        let outcome = match preferred_mode {
            Some(mode) => {
                let mut aux = IntelAux::new(&mmio, ddi);
                crate::dp_link_training::read_caps(&mut aux)
                    .map_err(|_| ModesetError::EdidUnavailable)
                    .and_then(|caps| {
                        let source = crate::dp_link_training::SourceCaps {
                            max_rate: crate::intel_gpu_dp::source_caps(Some(family), ddi).max_rate,
                            max_lanes,
                        };
                        let plan = crate::dp_link_training::negotiate(
                            &source,
                            &caps,
                            crate::dp_link_training::stream_demand_kbps(mode.pixel_clock_khz, 24),
                        );
                        modeset
                            .modeset_with_plan(
                                &fb,
                                &mode,
                                crate::intel_gpu_modeset::LinkPlan {
                                    rate: plan.rate,
                                    lanes: plan.lanes,
                                },
                            )
                            .map(|(mode, _)| mode)
                    })
            }
            None => Err(ModesetError::EdidUnavailable),
        };
        match outcome {
            Ok(mode) => {
                intel_gpu_multipipe::reprogram_active_dbuf_shares(&mmio);
                let _ = writeln!(
                    narf_console::Writer,
                    "  intel-gpu/dp: modeset OK on DDI {:?} / Pipe {:?}: {}x{} @ {} kHz pclk",
                    ddi,
                    pipe,
                    mode.h_active,
                    mode.v_active,
                    mode.pixel_clock_khz,
                );
                // Per-modeset VRR compute (Pipe A only): the timings
                // are recomputed from the mode this modeset committed
                // and the range a fresh AUX read reports for the sink,
                // instead of reusing install-time timings. An
                // unreachable AUX (or a non-capable sink) clears the
                // stored range/timings, so no stale timings can ever
                // engage VRR for an unknown sink.
                // VRR is Gen12's (Ice Lake has none).
                if let (crate::intel_gpu_pipes::Pipe::A, Some(family)) = (pipe, family.gen12()) {
                    let ip = crate::intel_gpu_vrr::DisplayVrrIp::from_gen12_platform(family);
                    let range = crate::intel_gpu_dp::vrr_range_from_aux(&mmio, ddi);
                    // VRR readback/sanitize at modeset setup (#1772):
                    // reconcile any GOP-left VRR state on Pipe A
                    // before the per-modeset compute publishes fresh
                    // timings. The atomic-path surface is the install
                    // hook's job (no card index in scope here); the
                    // sequencing lane (#1769) owns publishing modeset
                    // results to the card.
                    crate::intel_gpu_vrr::reconcile_vrr_at_setup(
                        &mmio,
                        crate::intel_gpu_vrr::VrrTranscoder::A,
                        ip,
                        1,
                    );
                    crate::intel_gpu_vrr::recompute_timings_for_modeset(
                        1,
                        &mode,
                        range,
                        ip,
                        crate::intel_gpu_vrr::VrrComputeOpts::default(),
                        crate::intel_gpu_vrr::VrrConnectorKind::DisplayPort,
                    );
                    // The sink's MSA-ignore bit follows the VRR
                    // state at every modeset (see `activate_on_pipe`).
                    let _ = crate::intel_gpu_dp::set_msa_timing_par_ignore(
                        &mmio,
                        ddi,
                        crate::intel_gpu_vrr::msa_timing_par_ignore_wanted(1),
                    );
                }
                // The native pipe/surface witnesses above precede
                // publication. The retained session serial makes a later
                // detach exact even if another output supersedes this image.
                intel_gpu::publish_external_scanout(
                    narf_graphics_driver::generic::GenericFb::new(
                        alloc.phys_base(),
                        u32::from(mode.h_active),
                        u32::from(mode.v_active),
                        fb.stride_bytes,
                        32,
                    ),
                    publication_serial,
                );
                Ok(())
            }
            Err(ModesetError::EdidUnavailable) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  intel-gpu/dp: EDID unavailable on DDI {:?} — no sink mode known yet",
                    ddi,
                );
                Err(DpBridgeError::EdidUnavailable)
            }
            Err(e) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  intel-gpu/dp: modeset on DDI {:?} / Pipe {:?} returned {:?}",
                    ddi,
                    pipe,
                    e,
                );
                Err(DpBridgeError::ModesetFailed)
            }
        }
    }
}

/// Scanouts stay retained until the owning session proves a local stop.
/// Failed stop never frees backing or recycles its pipe for another user.
static BRIDGE_SCANOUTS: IrqSafeSpinLock<[Option<ContiguousScanout>; 9]> =
    IrqSafeSpinLock::new([None; 9]);

fn stop_session(gpu: &intel_gpu::DisplayInfo, ddi: Ddi) -> Result<(), DpBridgeError> {
    let mut sessions = SESSIONS.try_lock().ok_or(DpBridgeError::NotReady)?;
    let Some(session) = sessions[ddi as usize] else {
        return Ok(());
    };
    if session.bar != gpu.gtt_mmadr.phys.raw() {
        return Err(DpBridgeError::NotReady);
    }
    let family = bridge_family(gpu.chip).ok_or(DpBridgeError::NotReady)?;
    let io = MmioRegionWindow::new(
        &gpu.gtt_mmadr,
        family,
        crate::intel_gpu_gen12_combo_phy::is_tgl_uy(gpu.chip.did),
    );
    if let Some(pipe) = session.pipe {
        let mut modeset = Modeset::for_pipe(&io, ddi, pipe);
        modeset.set_source_family(family);
        modeset
            .try_teardown()
            .map_err(|_| DpBridgeError::ModesetFailed)?;
    }
    match session.port {
        BridgePort::Dekel(port) => {
            port.disable(&io)
                .map_err(|_| DpBridgeError::ModesetFailed)?;
            port.disconnect(&io, session.bar)
                .map_err(|_| DpBridgeError::ModesetFailed)?;
        }
        BridgePort::Mg(port) => {
            port.disable(&io)
                .map_err(|_| DpBridgeError::ModesetFailed)?;
            port.disconnect(&io, TcMode::DpAlt);
        }
    }
    if let Some(pipe) = session.pipe {
        intel_gpu_multipipe::release_pipe(pipe, ddi);
    }
    // Stop is locally proven at this point. Withdraw before releasing the
    // physical backing; a stale serial is a no-op and therefore cannot blank
    // a newer internal, SST or Display-14 publication.
    intel_gpu::withdraw_external_scanout(session.publication_serial);
    let allocation = BRIDGE_SCANOUTS.lock()[ddi as usize].take();
    if let Some(allocation) = allocation {
        crate::intel_gpu_gtt::free_contiguous_scanout(&allocation);
    }
    sessions[ddi as usize] = None;
    Ok(())
}

fn retain_bridge_scanout(ddi: Ddi, alloc: ContiguousScanout) {
    let mut slots = BRIDGE_SCANOUTS.lock();
    let slot = &mut slots[ddi as usize];
    if let Some(old) = slot.take() {
        crate::intel_gpu_gtt::free_contiguous_scanout(&old);
    }
    *slot = Some(alloc);
}

/// One-shot EDID readback over AUX. Parses the panel's base block,
/// extracts the preferred detailed-timing descriptor (offset 0x36
/// — VESA E-EDID 1.4 §3.10), and converts to our [`Mode`].
///
/// Returns `None` on any failure (AUX unreachable, bad header,
/// checksum mismatch, no preferred timing in the descriptor slot)
/// — the modeset orchestrator's fallback path picks up.
///
/// Reference: Linux `drivers/gpu/drm/drm_edid.c::drm_edid_block_valid`
/// (header/checksum) + `drm_mode_detailed` (descriptor → drm_mode
/// conversion). VESA E-EDID 1.4 §3.10 (Detailed Timing Descriptor).
fn read_preferred_mode_via_aux<M: MmioWindow + ?Sized>(mmio: &M, ddi: Ddi) -> Option<Mode> {
    let mut aux = IntelAux::new(mmio, ddi);
    let mut buf = [0u8; 128];
    let edid = read_panel_edid(&mut aux, &mut buf).ok()?;
    let dt = edid.preferred_timing().ok()?;
    Some(detailed_timing_to_mode(&dt))
}

/// Convert a VESA E-EDID detailed-timing descriptor to our [`Mode`].
///
/// EDID descriptor field layout vs. our `Mode`:
///   `h_active`     → `h_active`
///   `h_blanking`   → `h_total = h_active + h_blanking`
///   `h_sync_offset`→ `h_sync_start = h_active + h_sync_offset` (front porch)
pub(crate) fn detailed_timing_to_mode(dt: &narf_graphics::edid::DetailedTiming) -> Mode {
    let h_total = dt.h_active.saturating_add(dt.h_blanking);
    let v_total = dt.v_active.saturating_add(dt.v_blanking);
    let h_sync_start = dt.h_active.saturating_add(dt.h_sync_offset);
    let h_sync_end = h_sync_start.saturating_add(dt.h_sync_width);
    let v_sync_start = dt.v_active.saturating_add(dt.v_sync_offset);
    let v_sync_end = v_sync_start.saturating_add(dt.v_sync_width);
    Mode {
        pixel_clock_khz: dt.pixel_clock_khz,
        h_active: dt.h_active,
        h_total,
        h_sync_start,
        h_sync_end,
        v_active: dt.v_active,
        v_total,
        v_sync_start,
        v_sync_end,
        h_sync_positive: dt.h_sync_positive,
        v_sync_positive: dt.v_sync_positive,
    }
}

// ── Registration ──────────────────────────────────────────────────

/// Stage::Late initcall — register the Intel bridge with the
/// DP-Alt-Mode bridge registry. Called from
/// [`crate::register_initcalls`]; the bridge is registered even if
/// no Intel iGPU is probed (the bridge returns `NoSuchConnector`
/// for every connector in that case, so dispatch falls through to
/// the next registered bridge).
pub fn register_bridge() {
    let bridge: Arc<dyn DpAltModeGpuBridge> = Arc::new(IntelDpBridge::new());
    dp_gpu_bridge::register_bridge(bridge);
}

// Marker so callers can `format!("{}", IntelDpBridge::name())` etc.
impl fmt::Display for IntelDpBridge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_connector_to_ddi_maps_tc1_through_tc6() -> TestResult {
        let wants = [
            (0, Ddi::D),
            (1, Ddi::E),
            (2, Ddi::F),
            (3, Ddi::G),
            (4, Ddi::H),
            (5, Ddi::I),
        ];
        for (idx, want) in wants.iter().copied() {
            match super::connector_to_ddi(ConnectorId::from_index(idx)) {
                Some(d) if d == want => {}
                other => {
                    let _ = other;
                    return TestResult::Fail("connector→DDI map mismatch");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_dp_bridge",
        smoke_connector_to_ddi_maps_tc1_through_tc6
    );

    /// Ice Lake's TC1..TC4 are DDI C..F; EHL/JSL and Gen9 have no Type-C
    /// connectors for the bridge.
    fn smoke_connector_to_ddi_for_ice_lake() -> TestResult {
        use crate::intel_gpu_gt::{Gen11Platform, Gen12Platform, Gen9Platform};
        let icl = SourceFamily::Gen11(Gen11Platform::IceLake);
        for (idx, want) in [(0, Ddi::C), (1, Ddi::D), (2, Ddi::E), (3, Ddi::F)] {
            if super::connector_to_ddi_for(icl, ConnectorId::from_index(idx)) != Some(want) {
                return TestResult::Fail("Ice Lake TC1..TC4 must map to DDI C..F");
            }
        }
        let tgl = SourceFamily::Gen12(Gen12Platform::TigerLake);
        if super::connector_to_ddi_for(icl, ConnectorId::from_index(4)).is_some()
            || super::connector_to_ddi_for(tgl, ConnectorId::from_index(0)) != Some(Ddi::D)
            || super::connector_to_ddi_for(
                SourceFamily::Gen11(Gen11Platform::ElkhartLake),
                ConnectorId::from_index(0),
            )
            .is_some()
            || super::connector_to_ddi_for(
                SourceFamily::Gen9 {
                    platform: Gen9Platform::KabyLake,
                    sku: crate::intel_gpu_gen9_ddi::SkuFamily::Ult,
                },
                ConnectorId::from_index(0),
            )
            .is_some()
        {
            return TestResult::Fail("only Gen12 and Ice Lake have bridge connectors");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_dp_bridge",
        smoke_connector_to_ddi_for_ice_lake
    );

    fn smoke_connector_to_ddi_unmaps_out_of_range() -> TestResult {
        if super::connector_to_ddi(ConnectorId::from_index(6)).is_some() {
            return TestResult::Fail("connector 6 should be unmapped");
        }
        if super::connector_to_ddi(ConnectorId::from_index(100)).is_some() {
            return TestResult::Fail("connector 100 should be unmapped");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_dp_bridge",
        smoke_connector_to_ddi_unmaps_out_of_range
    );

    fn smoke_bridge_returns_no_such_connector_when_intel_unprobed() -> TestResult {
        // QEMU TCG without intel-gpu emulation: the controller slot
        // is empty and the bridge has nothing to bind. It must
        // surface `NoSuchConnector` so dispatch can fall through to
        // an AMD / NVIDIA bridge instead of claiming the port.
        use narf_usbpd::vdm::{DpConfigureVdo, DpPinAssignment};
        if intel_gpu::is_probed() {
            return TestResult::Skip("Intel iGPU is probed — not exercising the unprobed path");
        }
        let bridge = IntelDpBridge::new();
        let vdo = DpConfigureVdo::dfp_source(DpPinAssignment::C);
        let cfg = DpLinkConfig::from_vdo(ConnectorId::from_index(0), &vdo);
        match bridge.enter_dp_mode(&cfg) {
            Err(DpBridgeError::NoSuchConnector) => TestResult::Pass,
            other => {
                let _ = other;
                TestResult::Fail("expected NoSuchConnector when Intel iGPU isn't probed")
            }
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_dp_bridge",
        smoke_bridge_returns_no_such_connector_when_intel_unprobed
    );

    fn smoke_bridge_rejects_out_of_range_connector_even_when_probed() -> TestResult {
        use narf_usbpd::vdm::{DpConfigureVdo, DpPinAssignment};
        let bridge = IntelDpBridge::new();
        let vdo = DpConfigureVdo::dfp_source(DpPinAssignment::C);
        // Connector index 99 — past TC5 even on the widest TGL part.
        let cfg = DpLinkConfig::from_vdo(ConnectorId::from_index(99), &vdo);
        match bridge.enter_dp_mode(&cfg) {
            Err(DpBridgeError::NoSuchConnector) => TestResult::Pass,
            other => {
                let _ = other;
                TestResult::Fail("expected NoSuchConnector for connector 99")
            }
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_dp_bridge",
        smoke_bridge_rejects_out_of_range_connector_even_when_probed
    );

    fn smoke_detailed_timing_to_mode_round_trip() -> TestResult {
        // 1920x1080 @ 60 Hz CVT-ish: pixel_clock 148.5 MHz,
        // h_active 1920, h_blanking 280, h_sync_offset 88, h_sync_width 44.
        let dt = narf_graphics::edid::DetailedTiming {
            pixel_clock_khz: 148_500,
            h_active: 1920,
            h_blanking: 280,
            v_active: 1080,
            v_blanking: 45,
            h_sync_offset: 88,
            h_sync_width: 44,
            v_sync_offset: 4,
            v_sync_width: 5,
            h_sync_positive: true,
            v_sync_positive: true,
        };
        let mode = super::detailed_timing_to_mode(&dt);
        if mode.h_active != 1920 || mode.v_active != 1080 {
            return TestResult::Fail("active not preserved");
        }
        if mode.h_total != 1920 + 280 {
            return TestResult::Fail("h_total = h_active + h_blanking");
        }
        if mode.v_total != 1080 + 45 {
            return TestResult::Fail("v_total = v_active + v_blanking");
        }
        if mode.h_sync_start != 1920 + 88 {
            return TestResult::Fail("h_sync_start = h_active + h_sync_offset");
        }
        if mode.h_sync_end != 1920 + 88 + 44 {
            return TestResult::Fail("h_sync_end = h_sync_start + h_sync_width");
        }
        if mode.v_sync_start != 1080 + 4 || mode.v_sync_end != 1080 + 4 + 5 {
            return TestResult::Fail("vertical sync packing");
        }
        if mode.pixel_clock_khz != 148_500 {
            return TestResult::Fail("pixel clock lost");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_dp_bridge",
        smoke_detailed_timing_to_mode_round_trip
    );

    fn smoke_detailed_timing_saturates_overflow() -> TestResult {
        // Synthetic descriptor with h_active near u16::MAX —
        // h_total must saturate rather than wrap.
        let dt = narf_graphics::edid::DetailedTiming {
            pixel_clock_khz: 1,
            h_active: u16::MAX - 10,
            h_blanking: 100,
            v_active: 10,
            v_blanking: 1,
            h_sync_offset: 5,
            h_sync_width: 5,
            v_sync_offset: 0,
            v_sync_width: 0,
            h_sync_positive: true,
            v_sync_positive: true,
        };
        let mode = super::detailed_timing_to_mode(&dt);
        if mode.h_total != u16::MAX {
            return TestResult::Fail("h_total should saturate at u16::MAX");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_dp_bridge",
        smoke_detailed_timing_saturates_overflow
    );
}
