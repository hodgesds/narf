//! AMD GPU bridge — wires DP Alt Mode → AMD display engine.
//!
//! Implements [`DpAltModeGpuBridge`] for the AMD GPU driver, registered
//! at Stage::Late under the `amdgpu` feature alongside
//! `amdgpu_usbc::start`. Before this bridge, `dp_gpu_bridge` could
//! never reach an AMD GPU: only `IntelDpBridge` implemented the trait
//! in production, so a DP Alt Mode entry on AMD completed in the PD
//! layer and then had no GPU consumer.
//!
//! ## What the bridge does (stage 1: resolve + record)
//!
//! On DP entry it resolves the negotiated link to a DMUB endpoint and
//! records it in a published table (`entered_links()`), returning `Ok`
//! to claim the connector for AMD. The modeset stage consumes the
//! recorded entry later; this bridge does not modeset itself (see
//! below).
//!
//! ## Resolution rule — a documented stage-1 assumption, not a map
//!
//! Three numbering spaces exist and no in-tree map connects them: the
//! PD layer's TCPM registry index (`ConnectorId`), the DMUB scan's
//! `(Channel, instance)` sink pairs, and ATOM/KMS connector indices.
//! `amdgpu_usbc` documents that a UCSI connector number is never a
//! GPU PHY/AUX index, and the spec repeats that no UCSI-to-GPU wiring
//! map is assumed. This bridge therefore does NOT invent a
//! connector→sink map. It resolves the entered link's endpoint class
//! from the published sink set:
//!
//! - A DPIA sink present → the link resolves to a DMUB tunnel endpoint
//!   (`Tunnel { instance }`, first DPIA sink in scan order). DPIA
//!   sinks are by construction USB-C tunneled endpoints: the scan
//!   publishes one only when its HPD is asserted, i.e. a sink is
//!   actually attached through the tunnel.
//! - Otherwise a Legacy sink → a native transmitter (`Native {
//!   instance }`, first Legacy sink in scan order). On silicon
//!   without DPIA the USB-C DP output is routed through the native
//!   transmitter via the mux.
//!
//! When several sinks of the resolved class are published, the first
//! in scan order is used and the entry is flagged `ambiguous` — a
//! later stage with board wiring (VBT/ATOM matching) refines it. The
//! ambiguity is recorded in the published entry and logged, not
//! hidden. Building that wiring map is follow-up work, not something
//! to guess here.
//!
//! ## What the bridge does NOT do
//!
//! - No modeset. Driving `amdgpu::set_mode` here would reprogram the
//!   primary display without pipe/encoder/connector binding. The
//!   bridge records the resolved entry; the modeset stage consumes it.
//! - No connector→sink identity map (see above).
//! - No exit hook: the trait has no exit path, so a re-entry on the
//!   same connector replaces the previous entry (same rule as the
//!   Intel bridge's retained scanout).
//!
//! ## Errors
//!
//! - AMD GPU not probed, or Navi22 (whose `amdgpu_usbc` scan never
//!   runs, so the bridge's sink source is absent) → `NoSuchConnector`:
//!   dispatch falls through to the next bridge.
//! - Probed but no sinks published yet → `NotReady`: the DP link is
//!   still alive on the wire and the caller retries later.

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};
use core::fmt;

use narf_drivers_usbpd::dp_gpu_bridge::{
    self, ConnectorId, DpAltModeGpuBridge, DpBridgeError, DpLinkConfig,
};
use narf_lib::sync::IrqSafeSpinLock;
use narf_usbpd::vdm::DpPinAssignment;

use crate::amdgpu;
use crate::amdgpu_dmub::Channel;
use crate::amdgpu_usbc::{self, Sink};

/// The DMUB endpoint a negotiated DP link resolves to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DpEndpoint {
    /// DMUB tunnelling endpoint: DPIA channel + instance.
    Tunnel { instance: u8 },
    /// Native DP transmitter: Legacy channel + instance.
    Native { instance: u8 },
}

/// A DP Alt Mode entry the bridge claimed, with its resolved endpoint.
/// Published via [`entered_links()`] for the modeset stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnteredDpLink {
    /// TCPM registry index of the connector that entered DP Alt Mode.
    pub connector: ConnectorId,
    /// DP lane count negotiated via Configure VDM (2 or 4).
    pub lanes: u8,
    /// Pin assignment selected (A/B/C/D/E/F per VESA §6).
    pub pin_assignment: DpPinAssignment,
    /// `signaling` nibble from the Configure VDO (RBR/HBR/HBR2/HBR3).
    pub signaling: u8,
    /// Multi-function preferred — 2-lane DP + 2-lane USB 3.x.
    pub multi_function: bool,
    /// Resolved DMUB endpoint (see module docs for the rule).
    pub endpoint: DpEndpoint,
    /// True when several sinks of the resolved class were published
    /// and the first in scan order was picked.
    pub ambiguous: bool,
}

/// Resolve an entered link's endpoint from the published sink set.
///
/// DPIA sinks win over Legacy sinks (see module docs); within the
/// winning class the first sink in scan order is picked. Returns
/// `None` when no sink is published at all.
pub(crate) fn resolve_endpoint(sinks: &[Sink]) -> Option<(DpEndpoint, bool)> {
    if let Some(sink) = sinks.iter().find(|s| s.channel == Channel::Dpia) {
        let ambiguous = sinks.iter().filter(|s| s.channel == Channel::Dpia).count() > 1;
        return Some((
            DpEndpoint::Tunnel {
                instance: sink.instance,
            },
            ambiguous,
        ));
    }
    if let Some(sink) = sinks.iter().find(|s| s.channel == Channel::Legacy) {
        let ambiguous = sinks
            .iter()
            .filter(|s| s.channel == Channel::Legacy)
            .count()
            > 1;
        return Some((
            DpEndpoint::Native {
                instance: sink.instance,
            },
            ambiguous,
        ));
    }
    None
}

/// Published DP-entered links, keyed by connector. Re-entry replaces.
#[derive(Debug, Default)]
struct EnteredTable {
    entries: Vec<EnteredDpLink>,
}

impl EnteredTable {
    fn record(&mut self, link: EnteredDpLink) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.connector == link.connector)
        {
            *entry = link;
        } else {
            self.entries.push(link);
        }
    }
}

static ENTERED: IrqSafeSpinLock<EnteredTable> = IrqSafeSpinLock::new(EnteredTable {
    entries: Vec::new(),
});

/// Snapshot of the DP-entered links the bridge has claimed, for the
/// modeset stage and diagnostics.
pub fn entered_links() -> Vec<EnteredDpLink> {
    ENTERED.lock().entries.clone()
}

/// AMD GPU bridge. Stateless — pulls the live sink set from
/// `amdgpu_usbc` on each call.
#[derive(Debug, Default)]
pub struct AmdDpBridge;

impl AmdDpBridge {
    pub const fn new() -> Self {
        AmdDpBridge
    }
}

impl DpAltModeGpuBridge for AmdDpBridge {
    fn name(&self) -> &'static str {
        "amdgpu"
    }

    fn enter_dp_mode(&self, cfg: &DpLinkConfig) -> Result<(), DpBridgeError> {
        // No AMD GPU, or a Navi22 dGPU whose usbc scan never runs:
        // this bridge can never resolve a sink here, so defer to the
        // next bridge in the registry instead of claiming the port.
        if !amdgpu::is_probed() || amdgpu::is_navi22() {
            return Err(DpBridgeError::NoSuchConnector);
        }
        let sinks = amdgpu_usbc::sinks();
        let Some((endpoint, ambiguous)) = resolve_endpoint(&sinks) else {
            return Err(DpBridgeError::NotReady);
        };
        let link = EnteredDpLink {
            connector: cfg.connector,
            lanes: cfg.lanes,
            pin_assignment: cfg.pin_assignment,
            signaling: cfg.signaling,
            multi_function: cfg.multi_function,
            endpoint,
            ambiguous,
        };
        ENTERED.lock().record(link);
        {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  amdgpu/dp: DP-Alt entered on {} ({} lanes, pin {:?}) → {:?}{}",
                cfg.connector,
                cfg.lanes,
                cfg.pin_assignment,
                endpoint,
                if ambiguous {
                    " (ambiguous: first of many sinks)"
                } else {
                    ""
                },
            );
        }
        Ok(())
    }
}

/// Stage::Late initcall — register the AMD bridge with the
/// DP-Alt-Mode bridge registry. Called from
/// [`crate::register_initcalls`]; the bridge is registered even if
/// no AMD GPU is probed (it returns `NoSuchConnector` for every
/// connector in that case, so dispatch falls through to the next
/// registered bridge).
pub fn register_bridge() {
    let bridge: Arc<dyn DpAltModeGpuBridge> = Arc::new(AmdDpBridge::new());
    dp_gpu_bridge::register_bridge(bridge);
}

// Marker so callers can `format!("{}", AmdDpBridge::name())` etc.
impl fmt::Display for AmdDpBridge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn sink(channel: Channel, instance: u8) -> Sink {
        Sink {
            channel,
            instance,
            dpcd: [0; 16],
            edid: Vec::new(),
        }
    }

    fn smoke_resolve_prefers_dpia_sink() -> TestResult {
        let sinks = [sink(Channel::Legacy, 0), sink(Channel::Dpia, 2)];
        match super::resolve_endpoint(&sinks) {
            Some((DpEndpoint::Tunnel { instance: 2 }, false)) => TestResult::Pass,
            _ => TestResult::Fail("DPIA sink should win, unambiguously"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu_dp_bridge",
        smoke_resolve_prefers_dpia_sink
    );

    fn smoke_resolve_falls_back_to_legacy_sink() -> TestResult {
        let sinks = [sink(Channel::Legacy, 1)];
        match super::resolve_endpoint(&sinks) {
            Some((DpEndpoint::Native { instance: 1 }, false)) => TestResult::Pass,
            _ => TestResult::Fail("lone Legacy sink should resolve to native"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu_dp_bridge",
        smoke_resolve_falls_back_to_legacy_sink
    );

    fn smoke_resolve_empty_is_none() -> TestResult {
        if super::resolve_endpoint(&[]).is_some() {
            return TestResult::Fail("no sinks should resolve to nothing");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu_dp_bridge", smoke_resolve_empty_is_none);

    fn smoke_resolve_flags_first_of_many_ambiguous() -> TestResult {
        let dpia = [sink(Channel::Dpia, 0), sink(Channel::Dpia, 1)];
        match super::resolve_endpoint(&dpia) {
            Some((DpEndpoint::Tunnel { instance: 0 }, true)) => {}
            _ => return TestResult::Fail("first DPIA of many should be ambiguous"),
        }
        let legacy = [sink(Channel::Legacy, 0), sink(Channel::Legacy, 3)];
        match super::resolve_endpoint(&legacy) {
            Some((DpEndpoint::Native { instance: 0 }, true)) => {}
            _ => return TestResult::Fail("first Legacy of many should be ambiguous"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu_dp_bridge",
        smoke_resolve_flags_first_of_many_ambiguous
    );

    fn smoke_entered_table_replaces_on_reentry() -> TestResult {
        use narf_usbpd::vdm::DpPinAssignment;
        let mut table = EnteredTable::default();
        let first = EnteredDpLink {
            connector: ConnectorId::from_index(0),
            lanes: 4,
            pin_assignment: DpPinAssignment::C,
            signaling: 0,
            multi_function: false,
            endpoint: DpEndpoint::Native { instance: 0 },
            ambiguous: false,
        };
        let mut second = first.clone();
        second.lanes = 2;
        second.pin_assignment = DpPinAssignment::D;
        second.multi_function = true;
        table.record(first);
        table.record(second);
        match table
            .entries
            .iter()
            .find(|e| e.connector == ConnectorId::from_index(0))
        {
            Some(entry) if entry.lanes == 2 && entry.multi_function => {}
            _ => return TestResult::Fail("re-entry should replace the prior entry"),
        }
        if table.entries.len() != 1 {
            return TestResult::Fail("re-entry should not duplicate the entry");
        }
        table.record(EnteredDpLink {
            connector: ConnectorId::from_index(1),
            lanes: 4,
            pin_assignment: DpPinAssignment::C,
            signaling: 0,
            multi_function: false,
            endpoint: DpEndpoint::Tunnel { instance: 1 },
            ambiguous: false,
        });
        if table.entries.len() != 2 {
            return TestResult::Fail("a second connector should add an entry");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu_dp_bridge",
        smoke_entered_table_replaces_on_reentry
    );

    fn smoke_bridge_returns_no_such_connector_when_amd_unprobed() -> TestResult {
        // QEMU TCG without AMD GPU emulation: the controller slot
        // is empty and the bridge has nothing to bind. It must
        // surface `NoSuchConnector` so dispatch can fall through to
        // another bridge instead of claiming the port.
        use narf_usbpd::vdm::{DpConfigureVdo, DpPinAssignment};
        if amdgpu::is_probed() {
            return TestResult::Skip("AMD GPU is probed — not exercising the unprobed path");
        }
        let bridge = AmdDpBridge::new();
        let vdo = DpConfigureVdo::dfp_source(DpPinAssignment::C);
        let cfg = DpLinkConfig::from_vdo(ConnectorId::from_index(0), &vdo);
        match bridge.enter_dp_mode(&cfg) {
            Err(DpBridgeError::NoSuchConnector) => TestResult::Pass,
            other => {
                let _ = other;
                TestResult::Fail("expected NoSuchConnector when AMD GPU isn't probed")
            }
        }
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu_dp_bridge",
        smoke_bridge_returns_no_such_connector_when_amd_unprobed
    );

    fn smoke_bridge_name_is_amdgpu() -> TestResult {
        if AmdDpBridge::new().name() != "amdgpu" {
            return TestResult::Fail("bridge name must be amdgpu");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu_dp_bridge", smoke_bridge_name_is_amdgpu);
}
