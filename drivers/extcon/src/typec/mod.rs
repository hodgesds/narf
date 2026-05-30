//! USB Type-C connector class.
//!
//! Linux ref: `drivers/usb/typec/class.c` + `include/linux/usb/typec.h`.
//!
//! A `TypecConnector` is a software representation of one USB-C
//! receptacle.  It tracks:
//!
//! - **Orientation** — which CC line is active (CC1 = normal, CC2 =
//!   flipped).  Decoded from the CC pull-up the TCPC reports
//!   (`CcStatus`).  Linux ref: `include/linux/usb/typec.h::
//!   typec_orientation`.
//!
//! - **Power Role** — Source / Sink / Dual-Role.  Negotiated via
//!   USB-PD or inferred from CC resistors for legacy cables.  Linux
//!   ref: `include/linux/usb/typec.h::typec_role`.
//!
//! - **Data Role** — Host (DFP) / Device (UFP) / Dual (DRP).  Linux
//!   ref: `include/linux/usb/typec.h::typec_data_role`.
//!
//! - **Entered Alt Modes** — list of currently active Alt Modes (DP,
//!   Thunderbolt, …).  Populated by `altmode.rs`.
//!
//! ## Relation to the lower layers
//!
//! ```text
//! TypecConnector          (this file)
//!   +- AltMode engine     (altmode.rs)  -- DP Alt Mode, TBT Alt Mode
//!   +- TypecMux trait     (mux.rs)      -- lane orientation + routing
//!   +- narf_usbpd::tcpc   (lower layer) -- raw CC state, PD frames
//! ```
//!
//! The connector holds an `Arc<dyn Tcpc>` so it can query CC state
//! for orientation detection without re-reading from the TCPM.

pub mod altmode;
pub mod mux;
pub mod pd;

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;
use narf_usbpd::tcpc::{CcState, CcStatus};

use crate::cable::Cable;
use crate::class::{ExtconDevice, ExtconEventSink};

pub use altmode::AltMode;
pub use mux::{MuxSetting, TypecMux};

// ── Orientation ────────────────────────────────────────────────────

/// Cable plug orientation, derived from which CC line carries the
/// pull-up.
///
/// Linux ref: `include/linux/usb/typec.h::typec_orientation`
/// (TYPEC_ORIENTATION_NONE, TYPEC_ORIENTATION_NORMAL,
/// TYPEC_ORIENTATION_REVERSE).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Orientation {
    /// Not yet determined (no cable attached).
    Unknown,
    /// CC1 is active — plug is in the "normal" orientation.
    Normal,
    /// CC2 is active — plug is flipped 180°.
    Reversed,
}

/// Determine cable orientation from a TCPC CC snapshot.
///
/// USB Type-C Spec 2.2 §4.5.1.3: the CC line that sees the partner
/// pull-up (or Rd) is the active lane. CC1 active → Normal; CC2
/// active → Reversed.
///
/// Logic mirrors `tcpm_set_cc_reflect()` in Linux's
/// `drivers/usb/typec/tcpm/tcpm.c`.
pub fn orientation_from_cc(cc: CcStatus) -> Orientation {
    let cc1_active = !matches!(cc.cc1, CcState::Open);
    let cc2_active = !matches!(cc.cc2, CcState::Open);
    match (cc1_active, cc2_active) {
        (true, false) => Orientation::Normal,
        (false, true) => Orientation::Reversed,
        // Both open (not attached) or both active (DRP toggling).
        _ => Orientation::Unknown,
    }
}

// ── Power / Data Role ──────────────────────────────────────────────

/// USB-C power role.
///
/// Linux ref: `include/linux/usb/typec.h::typec_role`
/// (TYPEC_SINK = 0, TYPEC_SOURCE = 1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerRole {
    Sink,
    Source,
    /// Dual-Role Power — not yet resolved.
    Dual,
}

/// USB-C data role.
///
/// Linux ref: `include/linux/usb/typec.h::typec_data_role`
/// (TYPEC_DEVICE = 0, TYPEC_HOST = 1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DataRole {
    /// UFP — USB peripheral / device.
    Device,
    /// DFP — USB host.
    Host,
    /// Not yet resolved (DRP before attachment).
    Dual,
}

// ── TypecConnector ─────────────────────────────────────────────────

/// One USB Type-C receptacle.
///
/// Tracks orientation, power + data roles, and entered Alt Modes.
/// Exposes cable state as an `ExtconDevice` so subscribers see
/// `Cable::Usb`, `Cable::UsbHost`, `Cable::Dp`, etc. change with
/// the port state.
///
/// Linux analogue: `struct typec_port` in `drivers/usb/typec/class.c`.
#[derive(Debug)]
pub struct TypecConnector {
    name: &'static str,
    inner: IrqSafeSpinLock<ConnectorState>,
}

struct ConnectorState {
    orientation: Orientation,
    power_role: PowerRole,
    data_role: DataRole,
    alt_modes: Vec<AltMode>,
    cable_states: [(Cable, bool); CABLE_COUNT],
    subscribers: Vec<Arc<dyn ExtconEventSink>>,
    mux: Option<Arc<dyn TypecMux>>,
}

impl core::fmt::Debug for ConnectorState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConnectorState")
            .field("orientation", &self.orientation)
            .field("power_role", &self.power_role)
            .field("data_role", &self.data_role)
            .field("alt_modes", &self.alt_modes)
            .field("cable_states", &self.cable_states)
            .field("subscribers_count", &self.subscribers.len())
            .finish_non_exhaustive()
    }
}

// Cables a Type-C connector can report.
const SUPPORTED: [Cable; CABLE_COUNT] = [
    Cable::Usb,
    Cable::UsbHost,
    Cable::FastCharger,
    Cable::SlowCharger,
    Cable::Hdmi,
    Cable::Dp,
    Cable::Dock,
    Cable::ThunderboltDock,
];
const CABLE_COUNT: usize = 8;

impl TypecConnector {
    /// Create a new Type-C connector with `name` as its stable
    /// identifier.
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            inner: IrqSafeSpinLock::new(ConnectorState {
                orientation: Orientation::Unknown,
                power_role: PowerRole::Dual,
                data_role: DataRole::Dual,
                alt_modes: Vec::new(),
                cable_states: SUPPORTED.map(|c| (c, false)),
                subscribers: Vec::new(),
                mux: None,
            }),
        }
    }

    /// Attach a `TypecMux` to this connector.  The mux is programmed
    /// whenever orientation or Alt Mode changes.
    pub fn set_mux(&self, mux: Arc<dyn TypecMux>) {
        self.inner.lock().mux = Some(mux);
    }

    /// Update orientation from a live CC reading and propagate to
    /// the mux if one is attached.
    pub fn update_cc(&self, cc: CcStatus) {
        let orient = orientation_from_cc(cc);
        let mut g = self.inner.lock();
        g.orientation = orient;
        // Propagate to mux if present.
        if let Some(mux) = g.mux.clone() {
            let setting = MuxSetting::from_orientation(orient);
            mux.configure(setting);
        }
    }

    /// Update the power role (called by the TCPM when a PD contract
    /// is established).
    pub fn set_power_role(&self, role: PowerRole) {
        self.inner.lock().power_role = role;
    }

    /// Update the data role.
    pub fn set_data_role(&self, role: DataRole) {
        self.inner.lock().data_role = role;
        let is_host = matches!(role, DataRole::Host);
        self.update_cable_state(Cable::UsbHost, is_host);
        self.update_cable_state(Cable::Usb, !is_host && !matches!(role, DataRole::Dual));
    }

    /// Mark an Alt Mode as entered (or exited) and update cable
    /// states + mux accordingly.
    pub fn set_alt_mode(&self, mode: AltMode, entered: bool) {
        let mut g = self.inner.lock();
        if entered {
            if !g.alt_modes.contains(&mode) {
                g.alt_modes.push(mode);
            }
        } else {
            g.alt_modes.retain(|m| *m != mode);
        }
        // Program the mux for the highest-priority active mode.
        if let Some(mux) = g.mux.clone() {
            let orient = g.orientation;
            let setting = if g.alt_modes.iter().any(|m| matches!(m, AltMode::DisplayPort(_))) {
                // DP takes 4 or 2 lanes depending on pin assignment.
                let dp_mode = g.alt_modes.iter().find_map(|m| {
                    if let AltMode::DisplayPort(p) = m { Some(*p) } else { None }
                });
                MuxSetting::dp(orient, dp_mode.unwrap_or(altmode::DpPinAssign::C))
            } else {
                MuxSetting::from_orientation(orient)
            };
            mux.configure(setting);
        }
        drop(g);
        // Update extcon cable bits.
        match mode {
            AltMode::DisplayPort(_) => self.update_cable_state(Cable::Dp, entered),
            AltMode::Thunderbolt(_) => self.update_cable_state(Cable::ThunderboltDock, entered),
        }
    }

    /// Snapshot of entered Alt Modes.
    pub fn entered_alt_modes(&self) -> Vec<AltMode> {
        self.inner.lock().alt_modes.clone()
    }

    /// Current orientation.
    pub fn orientation(&self) -> Orientation {
        self.inner.lock().orientation
    }

    /// Current power role.
    pub fn power_role(&self) -> PowerRole {
        self.inner.lock().power_role
    }

    /// Current data role.
    pub fn data_role(&self) -> DataRole {
        self.inner.lock().data_role
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Update one cable's attached state and notify subscribers if
    /// it changed.
    pub fn update_cable_state(&self, cable: Cable, attached: bool) {
        let mut g = self.inner.lock();
        let prev = g
            .cable_states
            .iter_mut()
            .find(|(c, _)| *c == cable);
        let changed = if let Some(slot) = prev {
            let old = slot.1;
            slot.1 = attached;
            old != attached
        } else {
            false
        };
        if !changed {
            return;
        }
        let name = self.name;
        let subs: Vec<_> = g.subscribers.clone();
        drop(g);
        for s in subs {
            s.on_cable_change(name, cable, attached);
        }
    }
}

impl ExtconDevice for TypecConnector {
    fn name(&self) -> &str {
        self.name
    }

    fn supported_cables(&self) -> &[Cable] {
        &SUPPORTED
    }

    fn cable_state(&self, cable: Cable) -> bool {
        self.inner
            .lock()
            .cable_states
            .iter()
            .find(|(c, _)| *c == cable)
            .map(|(_, s)| *s)
            .unwrap_or(false)
    }

    fn subscribe(&self, sink: Arc<dyn ExtconEventSink>) {
        self.inner.lock().subscribers.push(sink);
    }
}
