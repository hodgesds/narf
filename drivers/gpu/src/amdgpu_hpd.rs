//! AMD hotplug (HPD) state machine.
//!
//! Bridges the IH ring's HPD cookies into KMS connector state
//! transitions. Each external connector (DP, HDMI) has a
//! dedicated HPD pin; the GPU's DCN block monitors voltage on
//! the pin and raises an IH interrupt with `source_id =
//! SOURCE_ID_DCN_HPD` when it transitions. The IH cookie's
//! source-data payload encodes which connector instance fired.
//!
//! ## Reference
//!
//! - Linux `drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm_irq.c`
//!   (`handle_hpd_irq`, `handle_hpd_rx_irq`)
//! - Linux `drivers/gpu/drm/amd/display/include/grph_object_ctrl_defs.h`
//!   — HPD pin enumeration (`enum hpd_source_id`)
//! - Linux `drivers/gpu/drm/amd/display/dc/dce/dce_hwseq.c` —
//!   per-IP HPD register window
//!
//! GPL-2.0-or-later (matches NARF). Adapted directly.
//!
//! ## State machine
//!
//! ```text
//!   HPD low  ─ pin asserted   → enter Debounce(start = now)
//!   Debounce ─ pin stable ≥ 100ms → emit Connected
//!            ─ pin de-asserted     → back to Idle
//!   HPD high ─ pin de-asserted → emit Disconnected
//!   Any      ─ HPD_RX (DPCD ESI) → emit ShortPulse  (DP only)
//! ```
//!
//! Short-pulse vs long-pulse: DP spec splits HPD into two:
//!   - **Long pulse** ≥ 2 ms — connection/disconnection.
//!   - **Short pulse** 0.25–2 ms — DPCD event (link-status
//!     change, MST irq, sink-specific irq).
//!
//! HDMI has only the long-pulse semantic.

extern crate alloc;

use alloc::vec::Vec;

use crate::amdgpu_atom_displayobj::ConnectorKind;
use crate::amdgpu_modeset::{ConnectorStatus, KmsState};

// ── HPD source enumeration ───────────────────────────────────────
//
// DCN supports up to 6 HPD pins (per IP version). The IH cookie's
// dword 1 source-data field carries the pin index in bits[7:0].
// Per Linux's `hpd_source_id` enum.

/// HPD pin / source identifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HpdSource {
    Hpd1 = 0,
    Hpd2 = 1,
    Hpd3 = 2,
    Hpd4 = 3,
    Hpd5 = 4,
    Hpd6 = 5,
}

impl HpdSource {
    /// Decode from the IH cookie's source-data byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b & 0x07 {
            0 => Some(HpdSource::Hpd1),
            1 => Some(HpdSource::Hpd2),
            2 => Some(HpdSource::Hpd3),
            3 => Some(HpdSource::Hpd4),
            4 => Some(HpdSource::Hpd5),
            5 => Some(HpdSource::Hpd6),
            _ => None,
        }
    }
}

// ── HPD event kind ───────────────────────────────────────────────

/// Decoded HPD event kind. The IH cookie's source-data byte
/// carries a sub-id (in bits[12:8] per the spec) that
/// distinguishes long vs short pulse.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpdEventKind {
    /// Long pulse — pin transitioned to a stable state.
    /// Cookie bit indicates `Connect` (rising) or
    /// `Disconnect` (falling).
    LongPulseConnect,
    LongPulseDisconnect,
    /// Short pulse — DP-only DPCD event. Driver re-reads
    /// `DEVICE_SERVICE_IRQ_VECTOR` (DPCD 0x00201) to determine
    /// what changed.
    ShortPulse,
}

/// One IH-decoded HPD event ready for the state machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HpdEvent {
    pub source: HpdSource,
    pub kind: HpdEventKind,
    /// Per-driver timestamp (TSC tick or scheduler time). The
    /// debounce timer uses this to enforce the 100 ms stability
    /// window without pulling in scheduler types.
    pub tsc: u64,
}

impl HpdEvent {
    /// Decode an IH HPD cookie. dword 1 carries:
    ///   bits[7:0]  : HPD source index
    ///   bits[15:8] : sub-id (1 = connect, 0 = disconnect, 2 = short)
    pub fn from_ih_cookie(dword1: u32, tsc: u64) -> Option<Self> {
        let src = HpdSource::from_byte((dword1 & 0xFF) as u8)?;
        let sub = (dword1 >> 8) & 0xFF;
        let kind = match sub {
            0 => HpdEventKind::LongPulseDisconnect,
            1 => HpdEventKind::LongPulseConnect,
            2 => HpdEventKind::ShortPulse,
            _ => return None,
        };
        Some(Self {
            source: src,
            kind,
            tsc,
        })
    }
}

// ── Per-pin state machine ────────────────────────────────────────

/// Per-pin debounce state. Each external connector has one
/// `HpdPinState`. Internal panels (eDP / LVDS / DSI) don't have
/// HPD pins so they get `HpdPinState::Idle` permanently.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpdPinState {
    /// Pin idle (no HPD activity).
    Idle,
    /// Long pulse seen; waiting for stability.
    Debouncing { started_tsc: u64 },
    /// Pin stable + connected.
    Connected,
}

/// Debounce window in TSC ticks. Spec says 100 ms; tests pass
/// the value explicitly so they don't depend on TSC frequency.
pub const DEBOUNCE_TICKS_DEFAULT: u64 = 100_000_000; // 100ms at 1GHz TSC

/// HPD state machine — one per AMD GPU. Maps HPD source → pin
/// state and HPD source → connector index.
#[derive(Clone, Debug)]
pub struct HpdMachine {
    /// Per-source pin state, indexed by `HpdSource as usize`.
    pin_state: [HpdPinState; 6],
    /// Map HPD source → KMS connector index. `None` = no
    /// connector wired to this pin (typical: external GPUs only
    /// populate 2 or 3 of the 6 pins).
    source_to_connector: [Option<u8>; 6],
    /// Configurable debounce window. Tests override.
    debounce_ticks: u64,
}

impl Default for HpdMachine {
    fn default() -> Self {
        Self {
            pin_state: [HpdPinState::Idle; 6],
            source_to_connector: [None; 6],
            debounce_ticks: DEBOUNCE_TICKS_DEFAULT,
        }
    }
}

/// Outcome of feeding an HPD event through the state machine.
/// Caller acts on these (EDID readback for `Connected`, retrain
/// for `ShortPulse`, etc.).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpdOutcome {
    /// No state change (debouncing in progress, spurious event).
    NoChange,
    /// Pin stabilised at connected; readback EDID + update KMS.
    Connected { connector_idx: u8 },
    /// Pin transitioned to disconnected.
    Disconnected { connector_idx: u8 },
    /// Short pulse — DP-only; read DPCD ESI register.
    ShortPulse { connector_idx: u8 },
    /// Event arrived for a pin with no bound connector. The
    /// driver should log + drop.
    UnmappedSource,
}

impl HpdMachine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the debounce window. Default = 100ms equivalent.
    pub fn with_debounce(ticks: u64) -> Self {
        Self {
            debounce_ticks: ticks,
            ..Self::default()
        }
    }

    /// Bind HPD source `src` to connector index `connector_idx`.
    /// Reads in the topology table at probe time supply the
    /// mapping per ATOM's `GpuPinObject` enumeration.
    pub fn bind(&mut self, src: HpdSource, connector_idx: u8) {
        self.source_to_connector[src as usize] = Some(connector_idx);
    }

    /// Look up the connector bound to `src`.
    pub fn connector_for(&self, src: HpdSource) -> Option<u8> {
        self.source_to_connector[src as usize]
    }

    /// Feed one HPD event. Returns the outcome the caller should
    /// act on.
    pub fn handle(&mut self, event: HpdEvent) -> HpdOutcome {
        let src_idx = event.source as usize;
        let connector_idx = match self.source_to_connector[src_idx] {
            Some(c) => c,
            None => return HpdOutcome::UnmappedSource,
        };
        match event.kind {
            HpdEventKind::LongPulseConnect => {
                // Enter debounce; the next "stable check" or a
                // re-fire after the window will emit Connected.
                self.pin_state[src_idx] = HpdPinState::Debouncing {
                    started_tsc: event.tsc,
                };
                HpdOutcome::NoChange
            }
            HpdEventKind::LongPulseDisconnect => {
                let was = self.pin_state[src_idx];
                self.pin_state[src_idx] = HpdPinState::Idle;
                if matches!(was, HpdPinState::Connected) {
                    HpdOutcome::Disconnected { connector_idx }
                } else {
                    // Disconnect on a not-yet-stable pin: clear
                    // debounce, emit no event.
                    HpdOutcome::NoChange
                }
            }
            HpdEventKind::ShortPulse => HpdOutcome::ShortPulse { connector_idx },
        }
    }

    /// Sample the pin state at `tsc`. The debounce timer
    /// completes here. Call from the driver's main loop or a
    /// scheduled wakeup.
    pub fn sample_at(&mut self, src: HpdSource, tsc: u64) -> HpdOutcome {
        let src_idx = src as usize;
        let connector_idx = match self.source_to_connector[src_idx] {
            Some(c) => c,
            None => return HpdOutcome::NoChange,
        };
        if let HpdPinState::Debouncing { started_tsc } = self.pin_state[src_idx] {
            if tsc.saturating_sub(started_tsc) >= self.debounce_ticks {
                self.pin_state[src_idx] = HpdPinState::Connected;
                return HpdOutcome::Connected { connector_idx };
            }
        }
        HpdOutcome::NoChange
    }

    /// Apply an `HpdOutcome` to the KMS state. This is the
    /// glue between the HPD ISR and the KMS view. Returns the
    /// new status the KMS recorded (so caller can correlate
    /// with mode-set scheduling).
    pub fn apply_to_kms(kms: &mut KmsState, outcome: HpdOutcome) -> Option<ConnectorStatus> {
        match outcome {
            HpdOutcome::Connected { connector_idx } => {
                // Drop any stale status to ensure transition logic
                // fires even if a previous probe left Connected.
                kms.set_status(connector_idx, ConnectorStatus::Disconnected);
                kms.set_status(connector_idx, ConnectorStatus::Connected);
                Some(ConnectorStatus::Connected)
            }
            HpdOutcome::Disconnected { connector_idx } => {
                kms.set_status(connector_idx, ConnectorStatus::Disconnected);
                Some(ConnectorStatus::Disconnected)
            }
            // Short-pulse doesn't transition the KMS status; it
            // signals a DPCD event for the link layer.
            _ => None,
        }
    }

    /// `true` if a connector kind uses an HPD pin. Internal
    /// panels don't (the driver always treats them as Connected).
    pub fn connector_uses_hpd(kind: ConnectorKind) -> bool {
        matches!(
            kind,
            ConnectorKind::Dp
                | ConnectorKind::HdmiA
                | ConnectorKind::HdmiB
                | ConnectorKind::DviI
                | ConnectorKind::DviD
        )
    }

    /// `true` if a connector kind supports short-pulse HPD.
    /// DP/eDP only.
    pub fn supports_short_pulse(kind: ConnectorKind) -> bool {
        matches!(kind, ConnectorKind::Dp | ConnectorKind::Edp)
    }
}

/// Walk a batch of IH cookies, extract HPD events, return the
/// outcomes. Used by the driver's IH drainer.
pub fn drain_hpd_events(machine: &mut HpdMachine, events: &[HpdEvent]) -> Vec<HpdOutcome> {
    events.iter().map(|e| machine.handle(*e)).collect()
}

// ── Smoke tests ──────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use crate::amdgpu_atom_displayobj::{ConnectorKind, DisplayPath};
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_hpd_cookie_decode() -> TestResult {
        // Connect on HPD2.
        let dw1 = (HpdSource::Hpd2 as u32) | (1 << 8);
        let e = HpdEvent::from_ih_cookie(dw1, 1000).expect("decode");
        if e.source != HpdSource::Hpd2 {
            return TestResult::Fail("source wrong");
        }
        if e.kind != HpdEventKind::LongPulseConnect {
            return TestResult::Fail("kind wrong");
        }
        // Disconnect on HPD1.
        let dw1 = (HpdSource::Hpd1 as u32) | (0 << 8);
        let e = HpdEvent::from_ih_cookie(dw1, 0).unwrap();
        if e.kind != HpdEventKind::LongPulseDisconnect {
            return TestResult::Fail("disconnect not decoded");
        }
        // Short pulse on HPD3.
        let dw1 = (HpdSource::Hpd3 as u32) | (2 << 8);
        let e = HpdEvent::from_ih_cookie(dw1, 0).unwrap();
        if e.kind != HpdEventKind::ShortPulse {
            return TestResult::Fail("short pulse not decoded");
        }
        // Bad sub-id.
        let dw1 = (HpdSource::Hpd1 as u32) | (9 << 8);
        if HpdEvent::from_ih_cookie(dw1, 0).is_some() {
            return TestResult::Fail("bad sub-id should fail");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_hpd_cookie_decode);

    fn smoke_hpd_unmapped_source() -> TestResult {
        let mut m = HpdMachine::new();
        // No binds — event lands as UnmappedSource.
        let e = HpdEvent {
            source: HpdSource::Hpd1,
            kind: HpdEventKind::LongPulseConnect,
            tsc: 0,
        };
        if m.handle(e) != HpdOutcome::UnmappedSource {
            return TestResult::Fail("unbound source should be UnmappedSource");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_hpd_unmapped_source);

    fn smoke_hpd_debounce_emits_connected() -> TestResult {
        let mut m = HpdMachine::with_debounce(100);
        m.bind(HpdSource::Hpd2, 7);
        // Connect → debounce.
        let e = HpdEvent {
            source: HpdSource::Hpd2,
            kind: HpdEventKind::LongPulseConnect,
            tsc: 1000,
        };
        if m.handle(e) != HpdOutcome::NoChange {
            return TestResult::Fail("debounce entry should emit NoChange");
        }
        // Sample before window — still NoChange.
        if m.sample_at(HpdSource::Hpd2, 1050) != HpdOutcome::NoChange {
            return TestResult::Fail("pre-window sample should be NoChange");
        }
        // Sample after window — emits Connected.
        match m.sample_at(HpdSource::Hpd2, 1100) {
            HpdOutcome::Connected { connector_idx: 7 } => {}
            _ => return TestResult::Fail("post-window should emit Connected"),
        }
        // Resample is a no-op.
        if m.sample_at(HpdSource::Hpd2, 1500) != HpdOutcome::NoChange {
            return TestResult::Fail("stable resample should be NoChange");
        }
        // Disconnect → Disconnected emit.
        let e = HpdEvent {
            source: HpdSource::Hpd2,
            kind: HpdEventKind::LongPulseDisconnect,
            tsc: 2000,
        };
        match m.handle(e) {
            HpdOutcome::Disconnected { connector_idx: 7 } => {}
            _ => return TestResult::Fail("disconnect from stable should emit Disconnected"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_hpd_debounce_emits_connected);

    fn smoke_hpd_disconnect_during_debounce() -> TestResult {
        // Bounce: connect → disconnect before stable.
        let mut m = HpdMachine::with_debounce(100);
        m.bind(HpdSource::Hpd1, 0);
        m.handle(HpdEvent {
            source: HpdSource::Hpd1,
            kind: HpdEventKind::LongPulseConnect,
            tsc: 100,
        });
        let r = m.handle(HpdEvent {
            source: HpdSource::Hpd1,
            kind: HpdEventKind::LongPulseDisconnect,
            tsc: 150,
        });
        // Was debouncing, not connected → no Disconnected event.
        if r != HpdOutcome::NoChange {
            return TestResult::Fail("bouncy disconnect should suppress event");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_hpd_disconnect_during_debounce);

    fn smoke_hpd_short_pulse_passthrough() -> TestResult {
        let mut m = HpdMachine::new();
        m.bind(HpdSource::Hpd3, 5);
        let r = m.handle(HpdEvent {
            source: HpdSource::Hpd3,
            kind: HpdEventKind::ShortPulse,
            tsc: 0,
        });
        if r != (HpdOutcome::ShortPulse { connector_idx: 5 }) {
            return TestResult::Fail("short pulse should emit");
        }
        // Short pulse doesn't change pin state.
        if m.pin_state[HpdSource::Hpd3 as usize] != HpdPinState::Idle {
            return TestResult::Fail("short pulse altered pin state");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_hpd_short_pulse_passthrough);

    fn smoke_hpd_apply_to_kms() -> TestResult {
        let mut kms = KmsState::new(4);
        kms.ingest_atom_paths(
            [DisplayPath {
                device_tag: 0x80,
                connector_kind: ConnectorKind::Dp,
                connector_index: 0,
                gpu_object_id: 0x2100,
            }]
            .iter()
            .copied(),
        );
        // Initially Disconnected (external).
        if kms.connectors[0].status != ConnectorStatus::Disconnected {
            return TestResult::Fail("setup error: initial status");
        }
        // Connected outcome flips it.
        let r = HpdMachine::apply_to_kms(&mut kms, HpdOutcome::Connected { connector_idx: 0 });
        if r != Some(ConnectorStatus::Connected) {
            return TestResult::Fail("apply_to_kms didn't return Connected");
        }
        if kms.connectors[0].status != ConnectorStatus::Connected {
            return TestResult::Fail("KMS state not updated to Connected");
        }
        // Disconnected outcome flips it back.
        HpdMachine::apply_to_kms(&mut kms, HpdOutcome::Disconnected { connector_idx: 0 });
        if kms.connectors[0].status != ConnectorStatus::Disconnected {
            return TestResult::Fail("KMS state not flipped to Disconnected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_hpd_apply_to_kms);

    fn smoke_hpd_connector_capability() -> TestResult {
        // External connectors use HPD.
        for k in [ConnectorKind::Dp, ConnectorKind::HdmiA, ConnectorKind::DviI] {
            if !HpdMachine::connector_uses_hpd(k) {
                return TestResult::Fail("external should use HPD");
            }
        }
        // Internal don't.
        for k in [
            ConnectorKind::Edp,
            ConnectorKind::Lvds,
            ConnectorKind::Dsi,
            ConnectorKind::Vga,
        ] {
            if HpdMachine::connector_uses_hpd(k) {
                return TestResult::Fail("internal should not use HPD");
            }
        }
        // Short pulse: only DP/eDP.
        if !HpdMachine::supports_short_pulse(ConnectorKind::Dp) {
            return TestResult::Fail("DP should support short pulse");
        }
        if !HpdMachine::supports_short_pulse(ConnectorKind::Edp) {
            return TestResult::Fail("eDP should support short pulse");
        }
        if HpdMachine::supports_short_pulse(ConnectorKind::HdmiA) {
            return TestResult::Fail("HDMI should not support short pulse");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_hpd_connector_capability);

    fn smoke_drain_hpd_batch() -> TestResult {
        let mut m = HpdMachine::new();
        m.bind(HpdSource::Hpd1, 0);
        m.bind(HpdSource::Hpd2, 1);
        let events = [
            HpdEvent {
                source: HpdSource::Hpd1,
                kind: HpdEventKind::LongPulseConnect,
                tsc: 100,
            },
            HpdEvent {
                source: HpdSource::Hpd2,
                kind: HpdEventKind::ShortPulse,
                tsc: 200,
            },
        ];
        let outcomes = drain_hpd_events(&mut m, &events);
        if outcomes.len() != 2 {
            return TestResult::Fail("drain returned wrong count");
        }
        if outcomes[0] != HpdOutcome::NoChange {
            return TestResult::Fail("connect first should be NoChange");
        }
        if outcomes[1] != (HpdOutcome::ShortPulse { connector_idx: 1 }) {
            return TestResult::Fail("short pulse not emitted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_drain_hpd_batch);
}
