//! DisplayPort Alt Mode → GPU bridge — Stage-1 plumbing.
//!
//! When DP Alt Mode reaches the Configure / Active state on a USB-C
//! port, the GPU's DDI lanes have been physically routed to that
//! connector by the TCPC/TBT mux. The GPU driver still has to:
//!
//! 1. Bind a Pipe/Transcoder to the DDI port the connector lights up.
//! 2. Open an AUX channel over the USB-C aux pins to read DPCD + EDID.
//! 3. Pick a Mode and run a modeset.
//!
//! That work lives in `drivers/gpu/`. This module is the *seam*: a
//! trait the GPU driver implements + a slot the usbpd crate calls
//! into when Alt Mode goes Active. The two crates can't depend on
//! each other (usbpd is a transport, drivers/gpu wants to consume
//! it), so the bridge lives in usbpd-land and the gpu driver
//! registers an impl at init time.
//!
//! ## Wire shape
//!
//! - DP Alt Mode side calls [`notify_dp_entered`] from `altmode_dp`
//!   with the negotiated `DpConfigureVdo`. We derive `DpLinkConfig`
//!   (connector id, lane count, pin assignment) and forward it to
//!   the registered bridge.
//! - The bridge `enter_dp_mode()` impl can return early if its own
//!   Stage-2 work isn't done — the goal here is to land the call
//!   path, not the full modeset.
//! - On disconnect (cable yank / explicit DP exit) we eventually
//!   want a `[notify_dp_exited]`; Stage-1 ships just the entry path.
//!
//! ## Lane assignment per VESA DP Alt 2.0 §6
//!
//! Pin assignments map to lane counts:
//!
//! | Pin | Lanes (DP) | USB SS lanes |
//! |-----|------------|--------------|
//! |  A  |     4      |      0       | (deprecated USB-C plug)
//! |  B  |     2      |      2       | (deprecated)
//! |  C  |     4      |      0       | (USB-C plug)
//! |  D  |     2      |      2       | (USB-C plug)
//! |  E  |     4      |      0       | (USB-C native DP cable)
//! |  F  |     2      |      2       | (USB-C native DP cable)
//!
//! Odd-numbered pins (A/C/E) → 4 DP lanes; even (B/D/F) → 2.

extern crate alloc;

use alloc::sync::Arc;
use core::fmt;

use narf_lib::sync::IrqSafeSpinLock;
use narf_usbpd::vdm::{DpConfigureVdo, DpPinAssignment};

/// Stable identifier for a USB-C connector. The platform enumerates
/// every USB-C receptacle at init time; the TCPM port owns the
/// resulting `ConnectorId` for the lifetime of the boot.
///
/// In Stage-1 the connector id is the port-binding's index in the
/// TCPM registry — a small integer the GPU can map to a DDI via
/// `DpAltModeGpuBridge::connector_to_ddi` (the impl decides the
/// mapping; the gpu side knows which DDI is wired to which receptacle
/// on the actual board).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConnectorId(pub u32);

impl ConnectorId {
    pub const fn from_index(idx: u32) -> Self {
        ConnectorId(idx)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ConnectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "usbc{}", self.0)
    }
}

/// Description of the negotiated DP link, handed to the GPU when DP
/// Alt Mode reaches Active. Encodes everything the GPU needs to bind
/// a Pipe/Transcoder + DDI + start AUX traffic — without exposing the
/// inner VDM/PD types to the GPU driver.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DpLinkConfig {
    /// Which USB-C connector lit up.
    pub connector: ConnectorId,
    /// DP lane count negotiated via Configure VDM (2 or 4).
    pub lanes: u8,
    /// Pin assignment selected (A/B/C/D/E/F per VESA §6).
    pub pin_assignment: DpPinAssignment,
    /// `signaling` nibble from the Configure VDO — RBR/HBR/HBR2/HBR3
    /// bitmap (VESA DP Alt 2.0 §5.3). The GPU uses this to pick a
    /// link rate; Stage-1 just forwards it.
    pub signaling: u8,
    /// Multi-function preferred — 2-lane DP + 2-lane USB 3.x.
    pub multi_function: bool,
}

impl DpLinkConfig {
    /// Build a `DpLinkConfig` from the negotiated [`DpConfigureVdo`]
    /// produced by the DP Alt Mode state machine.
    pub fn from_vdo(connector: ConnectorId, cfg: &DpConfigureVdo) -> Self {
        let pin_assignment = pin_from_dfp_d_bitmap(cfg.dfp_d_pin);
        let lanes = lanes_for_pin(pin_assignment);
        // Multi-function pins are the even-numbered ones (B/D/F) per
        // §6.2.2 — they reserve two USB-SS lanes alongside the two
        // DP lanes.
        let multi_function = matches!(
            pin_assignment,
            DpPinAssignment::B | DpPinAssignment::D | DpPinAssignment::F
        );
        Self {
            connector,
            lanes,
            pin_assignment,
            signaling: cfg.signaling,
            multi_function,
        }
    }
}

/// Translate the `DpConfigureVdo.dfp_d_pin` bitmap to a single
/// `DpPinAssignment`. The Configure VDO carries exactly one bit set
/// (the DFP picks one pin assignment from the UFP's offered set when
/// it builds the Configure REQ — see `vdm::feed_response`'s
/// `EnteringMode` branch). If the bitmap is malformed we conservatively
/// fall back to pin C (4-lane DP only) — the universal default.
fn pin_from_dfp_d_bitmap(bitmap: u8) -> DpPinAssignment {
    match bitmap {
        x if x == DpPinAssignment::A as u8 => DpPinAssignment::A,
        x if x == DpPinAssignment::B as u8 => DpPinAssignment::B,
        x if x == DpPinAssignment::C as u8 => DpPinAssignment::C,
        x if x == DpPinAssignment::D as u8 => DpPinAssignment::D,
        x if x == DpPinAssignment::E as u8 => DpPinAssignment::E,
        x if x == DpPinAssignment::F as u8 => DpPinAssignment::F,
        _ => DpPinAssignment::C,
    }
}

/// VESA DP Alt Mode §6: pins A/C/E are 4-lane DP only; pins B/D/F
/// are 2-lane DP + 2-lane USB SS.
pub const fn lanes_for_pin(pin: DpPinAssignment) -> u8 {
    match pin {
        DpPinAssignment::A | DpPinAssignment::C | DpPinAssignment::E => 4,
        DpPinAssignment::B | DpPinAssignment::D | DpPinAssignment::F => 2,
    }
}

/// Error reported by a bridge impl. The GPU driver may legitimately
/// reject a DP-Alt enter — e.g. its own Stage-2 work isn't ready,
/// or the connector index doesn't map to a DDI on this silicon.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DpBridgeError {
    /// No DDI is wired to this USB-C connector on the current board.
    NoSuchConnector,
    /// The bridge implementation isn't ready yet (e.g. GPU probe
    /// hasn't completed, or modeset Stage-2 not landed). Caller
    /// should retry later; the DP link is still alive on the USB-C
    /// side.
    NotReady,
    /// EDID readback over the AUX channel failed; the bridge has
    /// the DDI bound but no sink-side mode is known yet.
    EdidUnavailable,
    /// Modeset programming failed mid-sequence (PLL lock / link
    /// training / etc.). The DDI binding is still active; the GPU
    /// stays dark.
    ModesetFailed,
}

/// What a GPU driver implements so DP Alt Mode can hand off the
/// physical port. The trait is intentionally tiny — the GPU side
/// owns the Pipe/Transcoder/DDI wiring; the bridge just tells it
/// "DP active on connector N with K lanes, here's the pin assignment".
pub trait DpAltModeGpuBridge: Send + Sync + fmt::Debug {
    /// Short tag for log messages — e.g. `"intel-gpu"` / `"amdgpu"`.
    fn name(&self) -> &'static str;

    /// DP Alt Mode reached `Active` — bind a DDI to `cfg.connector`,
    /// start AUX, run a modeset if a sink + EDID are reachable.
    ///
    /// Stage-1 contract: this *may* return Ok even if the eventual
    /// modeset is deferred (the bridge owns its own Stage-2 schedule).
    /// What it *must* do is decide whether the connector is wired to
    /// a real DDI on this silicon, so the caller can log "connected
    /// to DDI X" vs "no DDI here".
    fn enter_dp_mode(&self, cfg: &DpLinkConfig) -> Result<(), DpBridgeError>;
}

// ── Registry ───────────────────────────────────────────────────────

/// Process-wide bridge slot. GPU drivers register a single impl from
/// their Stage::Subsys initcall; the altmode-dp driver consults this
/// slot when a port reaches Active.
///
/// Multiple GPUs on one machine: the registry holds a small vec so an
/// Intel iGPU + an AMD dGPU can both register, and the DP-Alt path
/// asks each in turn. The first one to claim the connector wins. The
/// VESA spec doesn't preclude per-vendor wiring — the laptop firmware
/// resolves it via VBT / firmware tables.
static BRIDGES: IrqSafeSpinLock<alloc::vec::Vec<Arc<dyn DpAltModeGpuBridge>>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Register a GPU bridge. Idempotent on `name` — re-registering with
/// the same `name()` value replaces the prior entry rather than
/// stacking (some test setups re-run init).
pub fn register_bridge(bridge: Arc<dyn DpAltModeGpuBridge>) {
    let mut bridges = BRIDGES.lock();
    let nm = bridge.name();
    bridges.retain(|b| b.name() != nm);
    bridges.push(bridge);
}

/// Snapshot of registered bridges. Useful for diagnostics.
pub fn registered_bridges() -> alloc::vec::Vec<Arc<dyn DpAltModeGpuBridge>> {
    BRIDGES.lock().clone()
}

/// Drop every registered bridge — test-only.
#[doc(hidden)]
pub fn __test_reset_bridges() {
    BRIDGES.lock().clear();
}

/// Dispatch a DP Alt Mode `Active` event to every registered bridge.
/// Returns the first bridge that accepted the connector along with
/// its result; returns `None` if no bridge claims this connector.
/// The altmode_dp module calls this once per DP entry.
pub fn notify_dp_entered(cfg: &DpLinkConfig) -> Option<(&'static str, Result<(), DpBridgeError>)> {
    let bridges = BRIDGES.lock().clone();
    for b in bridges.iter() {
        let r = b.enter_dp_mode(cfg);
        match r {
            // Every error except NoSuchConnector counts as "this bridge
            // owns the connector, just couldn't finish yet". Caller
            // logs the outcome — the DP link is still up on the wire.
            Err(DpBridgeError::NoSuchConnector) => continue,
            other => return Some((b.name(), other)),
        }
    }
    None
}

// ── Smoke tests ────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    #[derive(Debug)]
    struct StubBridge {
        nm: &'static str,
        only_connector: Option<u32>,
        observed: IrqSafeSpinLock<Vec<DpLinkConfig>>,
    }
    impl StubBridge {
        fn new(nm: &'static str, only_connector: Option<u32>) -> Self {
            Self {
                nm,
                only_connector,
                observed: IrqSafeSpinLock::new(Vec::new()),
            }
        }
        fn observed_count(&self) -> usize {
            self.observed.lock().len()
        }
    }
    impl DpAltModeGpuBridge for StubBridge {
        fn name(&self) -> &'static str {
            self.nm
        }
        fn enter_dp_mode(&self, cfg: &DpLinkConfig) -> Result<(), DpBridgeError> {
            if let Some(c) = self.only_connector {
                if cfg.connector.as_u32() != c {
                    return Err(DpBridgeError::NoSuchConnector);
                }
            }
            self.observed.lock().push(*cfg);
            Ok(())
        }
    }

    fn smoke_lanes_for_pin_table() -> TestResult {
        if lanes_for_pin(DpPinAssignment::A) != 4 {
            return TestResult::Fail("pin A should be 4 lanes");
        }
        if lanes_for_pin(DpPinAssignment::B) != 2 {
            return TestResult::Fail("pin B should be 2 lanes");
        }
        if lanes_for_pin(DpPinAssignment::C) != 4 {
            return TestResult::Fail("pin C should be 4 lanes");
        }
        if lanes_for_pin(DpPinAssignment::D) != 2 {
            return TestResult::Fail("pin D should be 2 lanes");
        }
        if lanes_for_pin(DpPinAssignment::E) != 4 {
            return TestResult::Fail("pin E should be 4 lanes");
        }
        if lanes_for_pin(DpPinAssignment::F) != 2 {
            return TestResult::Fail("pin F should be 2 lanes");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usbpd/dp-gpu-bridge", smoke_lanes_for_pin_table);

    fn smoke_link_config_decodes_pin_d_as_2_lane_mf() -> TestResult {
        let vdo = DpConfigureVdo::dfp_source(DpPinAssignment::D);
        let cfg = DpLinkConfig::from_vdo(ConnectorId(2), &vdo);
        if cfg.connector != ConnectorId(2) {
            return TestResult::Fail("connector not preserved");
        }
        if cfg.lanes != 2 {
            return TestResult::Fail("pin D should give 2 lanes");
        }
        if cfg.pin_assignment != DpPinAssignment::D {
            return TestResult::Fail("pin assignment mismatch");
        }
        if !cfg.multi_function {
            return TestResult::Fail("pin D is multi-function");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/dp-gpu-bridge",
        smoke_link_config_decodes_pin_d_as_2_lane_mf
    );

    fn smoke_link_config_decodes_pin_c_as_4_lane_dp_only() -> TestResult {
        let vdo = DpConfigureVdo::dfp_source(DpPinAssignment::C);
        let cfg = DpLinkConfig::from_vdo(ConnectorId(0), &vdo);
        if cfg.lanes != 4 {
            return TestResult::Fail("pin C should give 4 lanes");
        }
        if cfg.multi_function {
            return TestResult::Fail("pin C is DP-only, not multi-function");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/dp-gpu-bridge",
        smoke_link_config_decodes_pin_c_as_4_lane_dp_only
    );

    fn smoke_pin_from_dfp_d_bitmap_falls_back_on_garbage() -> TestResult {
        // 0xFF has every pin bit set — Configure VDOs from the DFP
        // should never carry that, but the bridge must not panic.
        if super::pin_from_dfp_d_bitmap(0xFF) != DpPinAssignment::C {
            return TestResult::Fail("garbage bitmap should fall back to C");
        }
        if super::pin_from_dfp_d_bitmap(0x00) != DpPinAssignment::C {
            return TestResult::Fail("empty bitmap should fall back to C");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/dp-gpu-bridge",
        smoke_pin_from_dfp_d_bitmap_falls_back_on_garbage
    );

    fn smoke_notify_dp_entered_dispatch_picks_owning_bridge() -> TestResult {
        super::__test_reset_bridges();
        let a = Arc::new(StubBridge::new("bridge-a", Some(7)));
        let b = Arc::new(StubBridge::new("bridge-b", Some(3)));
        super::register_bridge(a.clone());
        super::register_bridge(b.clone());
        let vdo = DpConfigureVdo::dfp_source(DpPinAssignment::C);
        let cfg_3 = DpLinkConfig::from_vdo(ConnectorId(3), &vdo);
        let cfg_7 = DpLinkConfig::from_vdo(ConnectorId(7), &vdo);
        let cfg_42 = DpLinkConfig::from_vdo(ConnectorId(42), &vdo);
        match super::notify_dp_entered(&cfg_3) {
            Some(("bridge-b", Ok(()))) => {}
            _ => return TestResult::Fail("bridge-b should have claimed connector 3"),
        }
        match super::notify_dp_entered(&cfg_7) {
            Some(("bridge-a", Ok(()))) => {}
            _ => return TestResult::Fail("bridge-a should have claimed connector 7"),
        }
        if super::notify_dp_entered(&cfg_42).is_some() {
            return TestResult::Fail("no bridge owns connector 42");
        }
        if a.observed_count() != 1 || b.observed_count() != 1 {
            return TestResult::Fail("each bridge should see exactly one event");
        }
        super::__test_reset_bridges();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/dp-gpu-bridge",
        smoke_notify_dp_entered_dispatch_picks_owning_bridge
    );

    fn smoke_register_bridge_replaces_same_name() -> TestResult {
        super::__test_reset_bridges();
        let first = Arc::new(StubBridge::new("intel-gpu", None));
        let second = Arc::new(StubBridge::new("intel-gpu", None));
        super::register_bridge(first.clone());
        super::register_bridge(second.clone());
        if super::registered_bridges().len() != 1 {
            return TestResult::Fail("second registration should replace, not stack");
        }
        super::__test_reset_bridges();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/dp-gpu-bridge",
        smoke_register_bridge_replaces_same_name
    );
}
