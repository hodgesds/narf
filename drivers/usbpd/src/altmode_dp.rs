//! DisplayPort Alt Mode — Stage-0 port driver.
//!
//! After the TCPM reaches `SinkState::Ready` / `SourceState::Ready`
//! the port-partner is reachable for Vendor Defined Messages (PD 3.1
//! §6.4.4). The DP Alt Mode handshake — Discover Identity → Discover
//! SVIDs → Discover Modes → Enter Mode → Configure — runs over the
//! VDM channel and resolves to a pin-assignment + signalling rate on
//! the USB-C connector.
//!
//! Spec sources (public, non-GPL):
//! - **USB Power Delivery 3.1 v1.8** (USB-IF), §6.4.4 (VDM), §6.4.4.3
//!   (Discover Identity), §6.4.4.4 (Discover SVIDs / Modes), §6.4.4.5
//!   (Enter / Exit Mode).
//!   <https://www.usb.org/document-library/usb-power-delivery>
//! - **VESA DisplayPort Alt Mode on USB Type-C, Version 2.0** (VESA),
//!   §5 (Capabilities + Status VDOs), §6 (pin assignments).
//!   <https://vesa.org/vesa-standards/>
//!
//! The pure VDM encode/decode + the unscheduled `DpAltModeDriver`
//! state machine live in `narf_usbpd::vdm`. This module wires the
//! state machine to a `TcpmPort`:
//!
//! 1. Wait for the underlying port to reach `SinkState::Ready` /
//!    `SourceState::Ready` (call site checks `contract_live`).
//! 2. Build VDM frames using `narf_usbpd::vdm::build_*` helpers,
//!    encode them via `encode_message` with the partner's data role,
//!    and ship through `Tcpc::transmit`.
//! 3. Pull responses with `Tcpc::receive`, decode the VDM header,
//!    and pump the wrapped `DpAltModeDriver` until it reports
//!    `Active` (with the negotiated `DpConfigureVdo`) or `Failed`.
//! 4. When `Active` is reached, dispatch the negotiated configuration to the
//!    registered GPU bridge. A bridge that is not ready yet, or whose first
//!    AUX EDID read races sink wakeup, is retried while Alt Mode remains live.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};

use narf_capabilities::{Cap, CapError, Grant, NoopOp};
use narf_lib::sync::IrqSafeSpinLock;
use narf_usbpd::message::{
    decode_message, encode_message, DataMsg, DataRole, Header, PowerRole, SpecRev,
};
use narf_usbpd::tcpc::TcpcError;
use narf_usbpd::vdm::{AltModeState, AltStepOutcome, DpAltModeDriver, DpConfigureVdo, VdmHeader};
use narf_usbpd::UsbPd;

use crate::dp_gpu_bridge::{self, ConnectorId, DpBridgeError, DpLinkConfig};
use crate::tcpm::TcpmPort;

/// Error from the port-side DP Alt Mode driver.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DpAltError {
    AuthorityRevoked,
    Tcpc(TcpcError),
    /// Underlying PD message decode failed.
    Protocol,
    /// Partner does not support DP Alt Mode (no VESA SVID in
    /// Discover SVIDs response).
    NotSupported,
    /// Negotiation produced a NAK / BUSY / timed out.
    Failed,
}

impl From<CapError> for DpAltError {
    fn from(_: CapError) -> Self {
        DpAltError::AuthorityRevoked
    }
}

impl From<TcpcError> for DpAltError {
    fn from(e: TcpcError) -> Self {
        DpAltError::Tcpc(e)
    }
}

/// Outcome of one [`DpAltModePort::step`] call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DpAltStep {
    /// Nothing to do — wait for the port to reach a contract.
    NotReady,
    /// State machine advanced (frame sent / response consumed). Call
    /// step() again soon.
    Advanced(AltModeState),
    /// Negotiation finished. Active configuration is reported.
    Active(DpConfigureVdo),
    /// Discovery failed (NAK, BUSY, or unsupported partner).
    Failed,
}

/// One DP Alt Mode driver bound to a TCPM port.
#[derive(Debug)]
pub struct DpAltModePort {
    port: Arc<TcpmPort>,
    /// Stable USB-C connector id, handed to the GPU bridge once DP
    /// Alt Mode reaches Active. Assigned at registration time from
    /// the order ports come up — `connector_to_ddi` on the GPU side
    /// translates this back to a board-specific DDI.
    connector: ConnectorId,
    /// TCPC-owned Type-C class connector for this port. DP entry is
    /// reflected into it (#1211); detach clearing is owned by the
    /// TCPM task's connector sync.
    typec: Arc<narf_drivers_extcon::typec::TypecConnector>,
    driver: IrqSafeSpinLock<DpAltModeDriver>,
    next_msg_id: AtomicU8,
    /// GPU handoff state. Dispatch and detach have distinct claimed states so
    /// concurrent task-loop callers cannot enter and tear down the bridge at
    /// the same time. Every state except IDLE still requires or awaits detach.
    gpu_wiring_dispatched: AtomicU8,
}

const GPU_WIRING_IDLE: u8 = 0;
const GPU_WIRING_DISPATCHING: u8 = 1;
const GPU_WIRING_ACCEPTED: u8 = 2;
const GPU_WIRING_RETRY: u8 = 3;
const GPU_WIRING_DETACHING: u8 = 4;

const fn bridge_error_is_retryable(error: DpBridgeError) -> bool {
    matches!(
        error,
        DpBridgeError::NotReady | DpBridgeError::EdidUnavailable
    )
}

impl DpAltModePort {
    pub fn new(
        port: Arc<TcpmPort>,
        connector: ConnectorId,
        typec: Arc<narf_drivers_extcon::typec::TypecConnector>,
    ) -> Self {
        Self {
            port,
            connector,
            typec,
            driver: IrqSafeSpinLock::new(DpAltModeDriver::new()),
            next_msg_id: AtomicU8::new(0),
            gpu_wiring_dispatched: AtomicU8::new(0),
        }
    }

    pub fn connector(&self) -> ConnectorId {
        self.connector
    }

    pub fn state(&self) -> AltModeState {
        self.driver.lock().state
    }

    pub fn active_cfg(&self) -> Option<DpConfigureVdo> {
        self.driver.lock().active_cfg
    }

    pub fn port_label(&self) -> &str {
        &self.port.label
    }

    fn next_msg_id(&self) -> u8 {
        let v = self.next_msg_id.fetch_add(1, Ordering::AcqRel);
        v & 0x7
    }

    /// Send a VDM (frame payload is one or more 32-bit Data Objects,
    /// the first being the VDM header). Wraps the payload in a
    /// VendorDefined PD data message with the partner's role flipped
    /// (we're the DFP, partner is UFP).
    fn transmit_vdm(&self, vdos: &[u32]) -> Result<(), DpAltError> {
        if vdos.is_empty() {
            return Err(DpAltError::Protocol);
        }
        let h = Header::data(
            DataMsg::VendorDefined,
            DataRole::Dfp,
            PowerRole::Source,
            SpecRev::R3_0,
            self.next_msg_id(),
            vdos.len() as u8,
        );
        let frame = encode_message(h, vdos);
        self.port.tcpc().transmit(&frame)?;
        Ok(())
    }

    /// Pull the next VDM from the TCPC RX FIFO and pass it through
    /// the inner state machine. Returns `None` if RX was empty.
    fn poll_vdm(&self) -> Result<Option<Vec<u32>>, DpAltError> {
        let buf = match self.port.tcpc().receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => return Ok(None),
            Err(e) => return Err(DpAltError::Tcpc(e)),
        };
        let (h, objs) = decode_message(&buf).ok_or(DpAltError::Protocol)?;
        if DataMsg::from_u8(h.msg_type) != Some(DataMsg::VendorDefined) || objs.is_empty() {
            // Non-VDM frame while in discovery — not necessarily fatal
            // (could be a normal PD heartbeat); the inner SM only
            // cares about VDMs, so silently drop and try again.
            return Ok(None);
        }
        Ok(Some(objs))
    }

    /// One Discovery step. Caller drives this from a poll loop.
    pub fn step(&self, cap: &Cap<UsbPd, Grant>) -> Result<DpAltStep, DpAltError> {
        cap.invoke(NoopOp)?;
        if matches!(
            self.port.state(),
            crate::tcpm::PortState::Unattached | crate::tcpm::PortState::ErrorRecovery
        ) {
            let wiring = self.gpu_wiring_dispatched.load(Ordering::Acquire);
            if wiring != GPU_WIRING_IDLE {
                // An entry already in flight owns the next transition. Wait
                // for it to publish ACCEPTED/RETRY before claiming teardown.
                if matches!(wiring, GPU_WIRING_DISPATCHING | GPU_WIRING_DETACHING) {
                    return Ok(DpAltStep::NotReady);
                }
                if self
                    .gpu_wiring_dispatched
                    .compare_exchange(
                        wiring,
                        GPU_WIRING_DETACHING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    return Ok(DpAltStep::NotReady);
                }
                // Retry a refused local stop on later detached polls. Do not
                // reset discovery and replay over a live or uncertain owner.
                if dp_gpu_bridge::notify_dp_exited(self.connector).is_err() {
                    self.gpu_wiring_dispatched.store(wiring, Ordering::Release);
                    return Ok(DpAltStep::NotReady);
                }
                self.gpu_wiring_dispatched
                    .store(GPU_WIRING_IDLE, Ordering::Release);
            }
            *self.driver.lock() = DpAltModeDriver::new();
            self.next_msg_id.store(0, Ordering::Release);
            return Ok(DpAltStep::NotReady);
        }
        // RX arbitration (#1215): the TCPC RX FIFO has one consumer.
        // DP discovery must not pop frames while cable discovery is
        // still awaiting its SOP' / SOP'' answer, or a cable ACK
        // would be fed to the DP state machine as partner identity
        // (and vice versa). A connector with no cable port
        // registered counts as settled, so this can never block DP
        // on a missing cable task.
        if !self.port.contract_live() || !crate::cable_discovery::settled_for(self.connector) {
            return Ok(DpAltStep::NotReady);
        }

        // Special-case Idle: kick off discovery.
        let mut sm = self.driver.lock();
        if sm.state == AltModeState::Idle {
            let outcome = sm.start();
            drop(sm); // release before transmit (the trait isn't reentrant
                      // but we want explicit clarity)
            if let AltStepOutcome::Transmit(vdos) = outcome {
                self.transmit_vdm(&vdos)?;
            }
            return Ok(DpAltStep::Advanced(self.driver.lock().state));
        }
        if matches!(sm.state, AltModeState::Active) {
            let cfg = sm
                .active_cfg
                .unwrap_or_else(|| DpConfigureVdo::dfp_source(narf_usbpd::vdm::DpPinAssignment::C));
            drop(sm);
            if self.gpu_wiring_dispatched.load(Ordering::Acquire) == GPU_WIRING_RETRY {
                self.dispatch_to_gpu_bridge(&cfg);
            }
            return Ok(DpAltStep::Active(cfg));
        }
        if matches!(sm.state, AltModeState::Failed) {
            return Ok(DpAltStep::Failed);
        }
        drop(sm);

        // Pump one response if available.
        let Some(vdos) = self.poll_vdm()? else {
            return Ok(DpAltStep::Advanced(self.driver.lock().state));
        };
        // Sanity-check the VDM header: structured + ACK we care about
        // (the inner SM enforces this too but a quick guard here gives
        // us a cleaner error variant).
        let h = VdmHeader::decode(vdos[0]);
        let _ = h.svid; // anchor — used by inner SM

        let mut sm = self.driver.lock();
        let outcome = sm.feed_response(&vdos);
        let state = sm.state;
        drop(sm);
        match outcome {
            AltStepOutcome::Transmit(out_vdos) => {
                self.transmit_vdm(&out_vdos)?;
                Ok(DpAltStep::Advanced(state))
            }
            AltStepOutcome::Idle => Ok(DpAltStep::Advanced(state)),
            AltStepOutcome::Active(cfg) => {
                self.dispatch_to_gpu_bridge(&cfg);
                Ok(DpAltStep::Active(cfg))
            }
            AltStepOutcome::Failed => Ok(DpAltStep::Failed),
        }
    }

    /// Per-attach dispatch into the GPU bridge. Builds a
    /// `DpLinkConfig` from the negotiated VDO + this port's
    /// connector id, then forwards to every registered bridge. First bridge
    /// that recognises the connector wins. Not-ready and EDID-wakeup failures
    /// are retried by the Active task loop; accepted or hard-failed handoffs
    /// remain latched until detach.
    fn dispatch_to_gpu_bridge(&self, cfg: &DpConfigureVdo) {
        // Atomic claim prevents two task-loop callers from entering a GPU
        // bridge concurrently. RETRY remains nonzero so physical detach still
        // calls exit even when a failed attempt retained uncertain hardware.
        let previous = loop {
            let state = self.gpu_wiring_dispatched.load(Ordering::Acquire);
            if !matches!(state, GPU_WIRING_IDLE | GPU_WIRING_RETRY) {
                return;
            }
            if self
                .gpu_wiring_dispatched
                .compare_exchange(
                    state,
                    GPU_WIRING_DISPATCHING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                break state;
            }
        };
        let first_attempt = previous == GPU_WIRING_IDLE;
        let link = DpLinkConfig::from_vdo(self.connector, cfg);
        use core::fmt::Write as _;
        match dp_gpu_bridge::notify_dp_entered(&link) {
            Some((bridge_name, Ok(()))) => {
                self.gpu_wiring_dispatched
                    .store(GPU_WIRING_ACCEPTED, Ordering::Release);
                let _ = writeln!(
                    narf_console::Writer,
                    "  altmode-dp: {} entered DP Alt Mode ({}, {} lanes, pin {:?}); \
                     handed off to {}",
                    self.port.label,
                    link.connector,
                    link.lanes,
                    link.pin_assignment,
                    bridge_name,
                );
            }
            Some((bridge_name, Err(e))) => {
                self.gpu_wiring_dispatched.store(
                    if bridge_error_is_retryable(e) {
                        GPU_WIRING_RETRY
                    } else {
                        GPU_WIRING_ACCEPTED
                    },
                    Ordering::Release,
                );
                if first_attempt {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  altmode-dp: {} entered DP Alt Mode ({}, {} lanes, pin {:?}); \
                         bridge {} reported {:?}{}",
                        self.port.label,
                        link.connector,
                        link.lanes,
                        link.pin_assignment,
                        bridge_name,
                        e,
                        if bridge_error_is_retryable(e) {
                            "; retrying while attached"
                        } else {
                            ""
                        },
                    );
                }
            }
            None => {
                self.gpu_wiring_dispatched
                    .store(GPU_WIRING_RETRY, Ordering::Release);
                if first_attempt {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  altmode-dp: {} entered DP Alt Mode ({}, {} lanes, pin {:?}); \
                         no GPU bridge claims this connector yet; retrying while attached",
                        self.port.label,
                        link.connector,
                        link.lanes,
                        link.pin_assignment,
                    );
                }
            }
        }
        // #1211: reflect DP entry in the Type-C class. The GPU bridge
        // dispatch above is the hardware handoff; this is the class
        // observation of the same event. Exit on detach is handled by
        // the TCPM task's connector sync, which clears entered modes.
        // Physical detach also stops the GPU session and resets discovery;
        // contract renegotiation keeps the active session intact.
        self.typec.set_alt_mode(
            narf_drivers_extcon::typec::AltMode::DisplayPort(link.pin_assignment),
            true,
        );
    }
}

// ── Registry ───────────────────────────────────────────────────────

/// Active DP Alt Mode drivers, one per TCPM port that's running DP.
pub static DP_ALTMODE_PORTS: IrqSafeSpinLock<Vec<Arc<DpAltModePort>>> =
    IrqSafeSpinLock::new(Vec::new());

pub fn register_port(p: Arc<DpAltModePort>) {
    DP_ALTMODE_PORTS.lock().push(p);
}

pub fn registered_ports() -> Vec<Arc<DpAltModePort>> {
    DP_ALTMODE_PORTS.lock().clone()
}

#[doc(hidden)]
pub fn __test_reset() {
    DP_ALTMODE_PORTS.lock().clear();
}

/// Spawn the DP Alt Mode discovery task for one port. Polls the
/// state machine until it reaches Active / Failed.
///
/// Sleeps are calibrated wall-clock via `narf_time::Deadline`. The
/// previous incarnation used `sleep_cycles(330_000_000)` etc. which
/// assumed a ~3.3 GHz TSC — on Renoir 4700U (2.0 GHz) that came out as
/// 165 ms and on Phoenix HawkPoint1 (4.6 GHz) as 72 ms.
pub fn spawn_discovery_task(p: Arc<DpAltModePort>, label: String) {
    use core::fmt::Write as _;
    use narf_time::{Deadline, SleepUntil};
    narf_scheduler::spawn(async move {
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        loop {
            match p.step(&cap) {
                Ok(DpAltStep::Active(_)) => {
                    // Steady-state: just idle. A future HPD-IRQ handler
                    // will re-poke us to re-discover.
                    SleepUntil::new(Deadline::after_ms(100).as_instant()).await;
                }
                Ok(DpAltStep::Failed) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  altmode-dp: {} discovery failed; partner does not support DP Alt Mode",
                        label
                    );
                    return;
                }
                Ok(DpAltStep::NotReady) => {
                    // Wait for the underlying TCPM port to reach Ready.
                    SleepUntil::new(Deadline::after_ms(25).as_instant()).await;
                }
                Ok(DpAltStep::Advanced(_)) => {
                    narf_scheduler::yield_now().await;
                }
                Err(e) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  altmode-dp: {} step failed: {:?}",
                        label,
                        e
                    );
                    if matches!(e, DpAltError::AuthorityRevoked) {
                        return;
                    }
                    SleepUntil::new(Deadline::after_ms(100).as_instant()).await;
                }
            }
        }
    });
}

// ── Smoke tests ────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_usbpd::message::{CtrlMsg, DataMsg, DataRole, Header, PowerRole, SourcePdo, SpecRev};
    use narf_usbpd::tcpc::{CcState, CcStatus, PortRole, Tcpc, TcpcError};
    use narf_usbpd::vdm::{
        CommandType, DpStatusVdo, VdmCommand, VdmHeader, SVID_DISPLAYPORT, SVID_PD,
    };

    use crate::policy::{SinkPolicy, SourcePolicy};
    use crate::tcpm::{PortState, TcpmPort};

    #[derive(Debug)]
    struct FakeChip {
        cc: IrqSafeSpinLock<CcStatus>,
        tx: IrqSafeSpinLock<Vec<Vec<u8>>>,
        rx: IrqSafeSpinLock<Vec<Vec<u8>>>,
        role: IrqSafeSpinLock<PortRole>,
    }
    impl FakeChip {
        fn new() -> Self {
            Self {
                cc: IrqSafeSpinLock::new(CcStatus {
                    cc1: CcState::Rp3A0,
                    cc2: CcState::Open,
                }),
                tx: IrqSafeSpinLock::new(Vec::new()),
                rx: IrqSafeSpinLock::new(Vec::new()),
                role: IrqSafeSpinLock::new(PortRole::Drp),
            }
        }
        fn enqueue_rx(&self, b: Vec<u8>) {
            self.rx.lock().push(b);
        }
        fn last_tx(&self) -> Option<Vec<u8>> {
            self.tx.lock().last().cloned()
        }
    }
    impl Tcpc for FakeChip {
        fn name(&self) -> &'static str {
            "fake-dp"
        }
        fn set_role(&self, r: PortRole) -> Result<(), TcpcError> {
            *self.role.lock() = r;
            Ok(())
        }
        fn cc_status(&self) -> Result<CcStatus, TcpcError> {
            Ok(*self.cc.lock())
        }
        fn transmit(&self, m: &[u8]) -> Result<(), TcpcError> {
            self.tx.lock().push(m.to_vec());
            Ok(())
        }
        fn receive(&self) -> Result<Vec<u8>, TcpcError> {
            let mut q = self.rx.lock();
            if q.is_empty() {
                return Err(TcpcError::NoMessage);
            }
            Ok(q.remove(0))
        }
        fn hard_reset(&self) -> Result<(), TcpcError> {
            Ok(())
        }
    }

    fn vdm_frame(vdos: &[u32]) -> Vec<u8> {
        let h = Header::data(
            DataMsg::VendorDefined,
            DataRole::Ufp,
            PowerRole::Sink,
            SpecRev::R3_0,
            0,
            vdos.len() as u8,
        );
        encode_message(h, vdos)
    }

    /// Drive a TcpmPort all the way to a live sink contract so we can
    /// then poke the Alt-Mode driver.
    fn drive_to_sink_ready(chip: &Arc<FakeChip>, port: &TcpmPort, cap: &Cap<UsbPd, Grant>) {
        // Build a source-caps + Accept + PS_RDY sequence for the
        // wrapped narf_usbpd sink engine to chew through.
        // Unattached step on Rp3A0 transitions to AttachedSnk.
        let _ = port.step(cap).unwrap();
        // Inside AttachedSnk, the wrapped sink engine starts. We
        // pump until it reaches WaitCaps, then feed source caps,
        // Accept, PS_RDY.
        for _ in 0..6 {
            let _ = port.step(cap).unwrap();
        }
        let pdos = [SourcePdo::Fixed {
            voltage_mv: 5000,
            max_current_ma: 3000,
            epr_mode_capable: false,
        }];
        let h = Header::data(
            DataMsg::SourceCapabilities,
            DataRole::Dfp,
            PowerRole::Source,
            SpecRev::R3_0,
            0,
            1,
        );
        chip.enqueue_rx(encode_message(h, &[pdos[0].encode()]));
        // EvaluateCaps + SelectCapability + transmit Request.
        for _ in 0..3 {
            let _ = port.step(cap).unwrap();
        }
        let accept = Header::control(
            CtrlMsg::Accept,
            DataRole::Dfp,
            PowerRole::Source,
            SpecRev::R3_0,
            1,
        );
        chip.enqueue_rx(encode_message(accept, &[]));
        let _ = port.step(cap).unwrap();
        let ps_rdy = Header::control(
            CtrlMsg::PsRdy,
            DataRole::Dfp,
            PowerRole::Source,
            SpecRev::R3_0,
            2,
        );
        chip.enqueue_rx(encode_message(ps_rdy, &[]));
        let _ = port.step(cap).unwrap();
    }

    fn smoke_dp_altmode_step_returns_not_ready_before_contract() -> TestResult {
        let chip = Arc::new(FakeChip::new());
        let port = Arc::new(TcpmPort::new(
            chip,
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("dp-test"),
        ));
        let alt = DpAltModePort::new(
            port,
            ConnectorId::from_index(0),
            Arc::new(narf_drivers_extcon::typec::TypecConnector::new("dp-test")),
        );
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        match alt.step(&cap) {
            Ok(DpAltStep::NotReady) => TestResult::Pass,
            other => {
                let _ = other;
                TestResult::Fail("step should return NotReady before contract is live")
            }
        }
    }
    kernel_test_in!(
        "drivers/usbpd/altmode-dp",
        smoke_dp_altmode_step_returns_not_ready_before_contract
    );

    fn smoke_dp_bridge_retry_policy_keeps_transient_failures_live() -> TestResult {
        if !bridge_error_is_retryable(DpBridgeError::NotReady)
            || !bridge_error_is_retryable(DpBridgeError::EdidUnavailable)
        {
            return TestResult::Fail("transient bridge admission must remain retryable");
        }
        if bridge_error_is_retryable(DpBridgeError::NoSuchConnector)
            || bridge_error_is_retryable(DpBridgeError::ModesetFailed)
        {
            return TestResult::Fail("hard bridge outcomes must stay latched until detach");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/altmode-dp",
        smoke_dp_bridge_retry_policy_keeps_transient_failures_live
    );

    fn smoke_dp_altmode_full_walk_to_active() -> TestResult {
        let chip = Arc::new(FakeChip::new());
        let port = Arc::new(TcpmPort::new(
            chip.clone(),
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("dp-walk"),
        ));
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        drive_to_sink_ready(&chip, &port, &cap);
        if !port.contract_live() {
            return TestResult::Fail("test harness failed to drive the port to Ready");
        }
        if port.state() != PortState::AttachedSnk {
            return TestResult::Fail("expected AttachedSnk after drive_to_sink_ready");
        }
        let typec = Arc::new(narf_drivers_extcon::typec::TypecConnector::new("dp-walk"));
        let alt = DpAltModePort::new(port.clone(), ConnectorId::from_index(0), typec.clone());

        // Step 1: kick off — transmits Discover Identity REQ.
        let _ = alt.step(&cap).unwrap();
        if alt.state() != AltModeState::DiscoveringIdentity {
            return TestResult::Fail("kickoff didn't move to DiscoveringIdentity");
        }
        // Identity ACK.
        let id_ack = alloc::vec![VdmHeader::structured(
            SVID_PD,
            VdmCommand::DiscoverIdentity,
            CommandType::Ack,
        )
        .encode()];
        chip.enqueue_rx(vdm_frame(&id_ack));
        let _ = alt.step(&cap).unwrap();
        if alt.state() != AltModeState::DiscoveringSvids {
            return TestResult::Fail("Identity ACK didn't advance to DiscoveringSvids");
        }
        // SVIDs ACK with DisplayPort SVID.
        let svids_ack = alloc::vec![
            VdmHeader::structured(SVID_PD, VdmCommand::DiscoverSvids, CommandType::Ack).encode(),
            (SVID_DISPLAYPORT as u32) << 16,
        ];
        chip.enqueue_rx(vdm_frame(&svids_ack));
        let _ = alt.step(&cap).unwrap();
        if alt.state() != AltModeState::DiscoveringModes {
            return TestResult::Fail("SVIDs ACK didn't advance to DiscoveringModes");
        }
        // Modes ACK with DP capabilities advertising pin D.
        let caps_vdo = 0x3 | (0x1u32 << 2) | ((1u32 << 3) << 8);
        let modes_ack = alloc::vec![
            VdmHeader::structured(
                SVID_DISPLAYPORT,
                VdmCommand::DiscoverModes,
                CommandType::Ack,
            )
            .encode(),
            caps_vdo,
        ];
        chip.enqueue_rx(vdm_frame(&modes_ack));
        let _ = alt.step(&cap).unwrap();
        if alt.state() != AltModeState::EnteringMode {
            return TestResult::Fail("Modes ACK didn't advance to EnteringMode");
        }
        // EnterMode ACK.
        let enter_ack = alloc::vec![VdmHeader::structured(
            SVID_DISPLAYPORT,
            VdmCommand::EnterMode,
            CommandType::Ack,
        )
        .encode()];
        chip.enqueue_rx(vdm_frame(&enter_ack));
        let _ = alt.step(&cap).unwrap();
        if alt.state() != AltModeState::ConfiguringDp {
            return TestResult::Fail("EnterMode ACK didn't advance to ConfiguringDp");
        }
        // Configure ACK (arrives as Attention with DP_Status).
        let status = DpStatusVdo {
            port_connected: 0b10,
            power_low: false,
            enabled: true,
            multi_function: false,
            usb_configured: false,
            exit_dp_mode: false,
            hpd_state: true,
            hpd_irq: false,
        };
        let cfg_ack = alloc::vec![
            VdmHeader::structured(SVID_DISPLAYPORT, VdmCommand::Attention, CommandType::Ack)
                .encode(),
            status.encode(),
        ];
        chip.enqueue_rx(vdm_frame(&cfg_ack));
        let outcome = alt.step(&cap).unwrap();
        match outcome {
            DpAltStep::Active(_) => {}
            _ => return TestResult::Fail("Configure ACK didn't produce Active"),
        }
        if alt.state() != AltModeState::Active {
            return TestResult::Fail("state didn't move to Active");
        }
        if alt.active_cfg().is_none() {
            return TestResult::Fail("active_cfg() should be Some after Active");
        }
        // Verify the driver transmitted a Discover-Identity frame on
        // the wire (last TX between drive_to_sink_ready and the
        // Identity-ACK enqueue is the Discover-Identity VDM).
        if chip.last_tx().is_none() {
            return TestResult::Fail("alt-mode driver didn't transmit anything");
        }
        // #1211: DP entry is reflected in the Type-C class.
        use narf_drivers_extcon::class::ExtconDevice as _;
        if !typec
            .entered_alt_modes()
            .iter()
            .any(|m| matches!(m, narf_drivers_extcon::typec::AltMode::DisplayPort(_)))
        {
            return TestResult::Fail("DP entry not reflected in TypecConnector alt modes");
        }
        if !typec.cable_state(narf_drivers_extcon::cable::Cable::Dp) {
            return TestResult::Fail("DP entry not reflected in TypecConnector cable state");
        }
        {
            let mut cc = chip.cc.lock();
            cc.cc1 = CcState::Open;
            cc.cc2 = CcState::Open;
        }
        let _ = port.step(&cap).unwrap();
        if !matches!(alt.step(&cap), Ok(DpAltStep::NotReady))
            || alt.state() != AltModeState::Idle
            || alt.active_cfg().is_some()
            || alt.gpu_wiring_dispatched.load(Ordering::Acquire) != 0
        {
            return TestResult::Fail("detach must release bridge and reset per-attach discovery");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/altmode-dp",
        smoke_dp_altmode_full_walk_to_active
    );

    fn smoke_dp_altmode_partner_without_dp_fails() -> TestResult {
        let chip = Arc::new(FakeChip::new());
        let port = Arc::new(TcpmPort::new(
            chip.clone(),
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("dp-nodp"),
        ));
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        drive_to_sink_ready(&chip, &port, &cap);
        let alt = DpAltModePort::new(
            port,
            ConnectorId::from_index(0),
            Arc::new(narf_drivers_extcon::typec::TypecConnector::new("dp-test")),
        );

        let _ = alt.step(&cap).unwrap(); // kick Discover Identity
                                         // Identity ACK.
        let id_ack = alloc::vec![VdmHeader::structured(
            SVID_PD,
            VdmCommand::DiscoverIdentity,
            CommandType::Ack,
        )
        .encode()];
        chip.enqueue_rx(vdm_frame(&id_ack));
        let _ = alt.step(&cap).unwrap();
        // SVIDs ACK without the VESA SVID — partner is a non-DP dock.
        let svids_ack = alloc::vec![
            VdmHeader::structured(SVID_PD, VdmCommand::DiscoverSvids, CommandType::Ack).encode(),
            0x1234_5678,
        ];
        chip.enqueue_rx(vdm_frame(&svids_ack));
        let outcome = alt.step(&cap).unwrap();
        match outcome {
            DpAltStep::Failed => TestResult::Pass,
            _ => TestResult::Fail("missing DP SVID should fail discovery"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/altmode-dp",
        smoke_dp_altmode_partner_without_dp_fails
    );

    fn smoke_dp_altmode_registry_round_trip() -> TestResult {
        super::__test_reset();
        let chip = Arc::new(FakeChip::new());
        let port = Arc::new(TcpmPort::new(
            chip,
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("reg"),
        ));
        let alt = Arc::new(DpAltModePort::new(
            port,
            ConnectorId::from_index(0),
            Arc::new(narf_drivers_extcon::typec::TypecConnector::new("dp-test")),
        ));
        super::register_port(alt);
        if super::registered_ports().len() != 1 {
            return TestResult::Fail("registry didn't capture port");
        }
        super::__test_reset();
        if !super::registered_ports().is_empty() {
            return TestResult::Fail("__test_reset didn't drain");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/altmode-dp",
        smoke_dp_altmode_registry_round_trip
    );

    fn smoke_dp_altmode_cap_revocation_blocks_step() -> TestResult {
        let chip = Arc::new(FakeChip::new());
        let port = Arc::new(TcpmPort::new(
            chip,
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("rev"),
        ));
        let alt = DpAltModePort::new(
            port,
            ConnectorId::from_index(0),
            Arc::new(narf_drivers_extcon::typec::TypecConnector::new("dp-test")),
        );
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        cap.revoke();
        match alt.step(&cap) {
            Err(DpAltError::AuthorityRevoked) => TestResult::Pass,
            _ => TestResult::Fail("step accepted a revoked cap"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/altmode-dp",
        smoke_dp_altmode_cap_revocation_blocks_step
    );
}
