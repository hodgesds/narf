//! Intel iGPU bridge — wires DP Alt Mode → Intel display engine.
//!
//! Implements [`DpAltModeGpuBridge`] for the Intel iGPU driver. The
//! bridge sits between the USB-C side (which has just finished the
//! VESA DP-Alt VDM dance) and the display engine (Pipe / Transcoder /
//! DDI). Per VESA DP Alt Mode v2.0 §6 and Tiger Lake / Alder Lake
//! PRM Vol. 12 §"DDI Buffer", the source side does:
//!
//! 1. Map USB-C connector → DDI (TC1..TC5 → Ddi::D..H on Gen12).
//! 2. Bind a Pipe + Transcoder to that DDI.
//! 3. Open an AUX channel — DPCD reads now flow over the USB-C aux
//!    pins. EDID over I²C-over-AUX gives the sink's preferred mode.
//! 4. Run a modeset using the existing [`Modeset`] orchestrator.
//!
//! ## Stage-1 scope
//!
//! - **Owned by this file**: USB-C → DDI mapping, MMIO window
//!   adapter for the BAR0 `MmioRegion`, dispatch into AUX + Modeset.
//! - **Deferred to existing modeset Stage-2**: actual PLL / pipe /
//!   plane / link-training register writes. We call `Modeset::modeset`
//!   and propagate its outcome. The orchestrator's own TODOs (PLL
//!   programming, transcoder timing, plane setup) land in its own
//!   Stage-2.
//!
//! ## USB-C connector → DDI mapping
//!
//! On Tiger Lake / Alder Lake the Type-C ports are DDIs D, E, F, G,
//! H — i.e. TC1..TC5 in the PRM nomenclature. The platform firmware
//! (VBT) describes the *actual* wiring (some boards leave TC5
//! depopulated, etc.); without VBT parsing we use the canonical
//! "connector index N → DDI D+N" mapping. The board may not have a
//! USB-C jack physically attached at every DDI, but if Alt Mode
//! reached Active on connector N then there *is* one on the wire,
//! so the mapping is observed-correct.

extern crate alloc;

use alloc::sync::Arc;
use core::fmt;

use narf_driver_runtime::MmioRegion;
use narf_drivers_usbpd::dp_gpu_bridge::{
    self, ConnectorId, DpAltModeGpuBridge, DpBridgeError, DpLinkConfig,
};

use crate::dp_edid::read_panel_edid;
use crate::intel_gpu;
use crate::intel_gpu_aux::{IntelAux, MmioWindow};
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_modeset::{Framebuffer, Mode, Modeset, ModesetError, PixelFormat};

/// Map a USB-C [`ConnectorId`] to the Gen12 Type-C DDI it's wired
/// to. Returns `None` if the index is outside the documented TC1..5
/// range (Tiger Lake / Alder Lake top out at 5 TC ports — anything
/// higher is a board with extra hubs the GPU doesn't see directly).
///
/// PRM Vol. 12 §"Display DDI Port Index":
///   TC1 = Ddi::D, TC2 = Ddi::E, TC3 = Ddi::F, TC4 = Ddi::G, TC5 = Ddi::H.
pub fn connector_to_ddi(connector: ConnectorId) -> Option<Ddi> {
    match connector.as_u32() {
        0 => Some(Ddi::D),
        1 => Some(Ddi::E),
        2 => Some(Ddi::F),
        3 => Some(Ddi::G),
        4 => Some(Ddi::H),
        _ => None,
    }
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
}

impl<'a> MmioRegionWindow<'a> {
    fn new(region: &'a MmioRegion) -> Self {
        Self { region }
    }
}

impl<'a> MmioWindow for MmioRegionWindow<'a> {
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
        // Resolve the DDI for this USB-C connector. If the index
        // doesn't fit our Type-C mapping, pass — another bridge
        // (amdgpu / nvidia) might own this connector.
        let Some(ddi) = connector_to_ddi(cfg.connector) else {
            return Err(DpBridgeError::NoSuchConnector);
        };

        // Need a live Intel iGPU controller. If we're on a non-Intel
        // platform, defer to the next bridge in the registry by
        // signalling "no connector here".
        if !intel_gpu::is_probed() {
            return Err(DpBridgeError::NoSuchConnector);
        }

        let mut outcome = Err(DpBridgeError::NotReady);
        intel_gpu::with_controller(|gpu| {
            outcome = self.bind_and_modeset(gpu, ddi, cfg);
        });
        outcome
    }
}

impl IntelDpBridge {
    fn bind_and_modeset(
        &self,
        gpu: &intel_gpu::IntelGpu,
        ddi: Ddi,
        cfg: &DpLinkConfig,
    ) -> Result<(), DpBridgeError> {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  intel-gpu/dp: DP-Alt active on {} (DDI {:?}, {} lanes, signaling=0x{:x}); \
             chip={} GMD_ID={:#010x}",
            cfg.connector,
            ddi,
            cfg.lanes,
            cfg.signaling,
            gpu.chip.asic,
            gpu.gmd_id,
        );

        let mmio = MmioRegionWindow::new(&gpu.gtt_mmadr);

        // Try an EDID readback over AUX. AUX may not yet be reachable
        // (DPRX side could still be waking up); a failure here isn't
        // fatal for the bridge contract — we just have no mode.
        let preferred_mode = read_preferred_mode_via_aux(&mmio, ddi);

        // Hand off to the existing modeset orchestrator. Stage-2
        // modeset returns early at several internal TODOs, which
        // surface here as ModesetError; we log + report `NotReady`
        // since the DDI binding is captured but the engine isn't lit.
        let mut modeset = Modeset::new(&mmio, ddi);
        let fb = stage1_placeholder_fb();
        match modeset.modeset(&fb, preferred_mode.as_ref()) {
            Ok(mode) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  intel-gpu/dp: modeset OK on DDI {:?}: {}x{} @ {} kHz pclk",
                    ddi,
                    mode.h_active,
                    mode.v_active,
                    mode.pixel_clock_khz,
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
                    "  intel-gpu/dp: modeset on DDI {:?} returned {:?} \
                     (modeset Stage-2 wiring deferred)",
                    ddi,
                    e,
                );
                Err(DpBridgeError::ModesetFailed)
            }
        }
    }
}

/// One-shot EDID readback over AUX. On any error we return `None`
/// and let the modeset orchestrator's hard-coded fallback path
/// decide. Eventually the EDID parser hands us a preferred timing
/// descriptor; until that lands as `narf-graphics::edid` glue, we
/// just exercise the AUX transport on real hardware.
fn read_preferred_mode_via_aux<M: MmioWindow + ?Sized>(mmio: &M, ddi: Ddi) -> Option<Mode> {
    let mut aux = IntelAux::new(mmio, ddi);
    let mut buf = [0u8; 128];
    let _ = read_panel_edid(&mut aux, &mut buf);
    // TODO: parse `buf` into a Mode once narf-graphics::edid exposes
    //       a `preferred_timing()` helper.
    None
}

/// Placeholder framebuffer for the modeset call. The modeset
/// orchestrator validates alignment but Stage-2 hasn't allocated a
/// real GGTT-mapped surface yet — we hand a clearly-bogus address
/// that satisfies the alignment check so the orchestrator can run
/// through its TODOs without panicking.
fn stage1_placeholder_fb() -> Framebuffer {
    Framebuffer {
        phys_addr: 0x0010_0000, // page-aligned, otherwise unused
        stride_bytes: 1920 * 4,  // 4-byte-per-pixel XRGB at 1920 wide
        format: PixelFormat::Xrgb8888,
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

    fn smoke_connector_to_ddi_maps_tc1_through_tc5() -> TestResult {
        let wants = [
            (0, Ddi::D),
            (1, Ddi::E),
            (2, Ddi::F),
            (3, Ddi::G),
            (4, Ddi::H),
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
        smoke_connector_to_ddi_maps_tc1_through_tc5
    );

    fn smoke_connector_to_ddi_unmaps_out_of_range() -> TestResult {
        if super::connector_to_ddi(ConnectorId::from_index(5)).is_some() {
            return TestResult::Fail("connector 5 should be unmapped");
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
}
