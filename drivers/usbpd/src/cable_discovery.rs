//! SOP' / SOP'' cable discovery — drives the decode-only `sop_prime`
//! codec from a live TCPM port and exposes the resulting cable
//! identity to policy and connection-manager layers (#1215).
//!
//! Before this module, `narf_usbpd::sop_prime` could decode cable
//! VDOs but nothing ever sent Discover Identity to a cable plug:
//! its only callers were tests. This module closes that gap with a
//! per-port state machine modelled on the DP Alt Mode discovery
//! task:
//!
//! ```text
//!   NotReady ──contract live──► DiscoveringPrime ──ACK──► Done
//!        ▲                          │  │  │
//!        │                     timeout│  │Nak (far only: partial Done)
//!        │                          ▼  ▼
//!        └────── detach ───── NotPresent / Failed / Unsupported
//! ```
//!
//! An active near plug that reports SOP'' support chains into a
//! second Discover Identity to the far plug (`DiscoveringDoublePrime`).
//!
//! ## RX arbitration with DP discovery
//!
//! The TCPC RX FIFO has one consumer at a time. Post-contract, the
//! DP task and this task would otherwise race for responses: a SOP
//! ACK popped by the cable task is lost to DP, and a SOP' ACK popped
//! by DP would be fed to the DP state machine as partner identity.
//! So DP discovery waits for cable discovery to settle: see
//! [`settled_for`] and the `NotReady` gate in
//! [`crate::altmode_dp::DpAltModePort::step`]. Cable discovery
//! settles fast (one round trip with an e-marker, or a bounded
//! poll timeout without one), and a connector with no cable port
//! registered counts as settled, so DP can never deadlock on a
//! missing cable task.
//!
//! ## What this module does NOT do
//!
//! - No USB4 / policy consumption of the identity yet: the exposure
//!   surface is [`CableDiscoveryPort::cable_identity`] plus the
//!   [`registered_ports`] registry. Consumers are follow-on lanes.
//! - No VPD VDO decode beyond the ID Header: VPD has its own VDO
//!   layout, stored here as header-only.
//! - No TPS65987 SOP' transmit: that chip's `transmit` is
//!   firmware-mediated, so it keeps the trait default
//!   (`Unsupported`) and the port settles as `Unsupported`.
//! - No retransmission: a lost request settles as `NotPresent` for
//!   this attach and is retried on the next attach.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};

use narf_capabilities::{Cap, CapError, Grant, NoopOp};
use narf_lib::sync::IrqSafeSpinLock;
use narf_usbpd::message::{DataMsg, DataRole, Header, PowerRole, SpecRev};
use narf_usbpd::sop_prime::{
    discover_identity_vdm_header, ActiveCableVdo1, IdHeaderVdo, PassiveCableVdo,
    CABLE_PLUG_TYPE_ACTIVE_CABLE, CABLE_PLUG_TYPE_PASSIVE_CABLE, CABLE_PLUG_TYPE_VPD,
};
use narf_usbpd::tcpc::{SopTarget, TcpcError};
use narf_usbpd::vdm::{CommandType, VdmCommand, VdmHeader, SVID_PD};
use narf_usbpd::UsbPd;

use crate::dp_gpu_bridge::ConnectorId;
use crate::tcpm::{PortState, TcpmPort};

/// Bounded wait for a cable-plug response, in RX polls.
/// Implementation timeout, NOT a PD spec constant: at the discovery
/// task's ~25 ms cadence this is ~1 s, chosen so a cable without an
/// e-marker settles promptly instead of spinning forever.
const MAX_RESPONSE_POLLS: u32 = 40;

/// One cable plug's decoded identity.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PlugIdentity {
    /// ID Header VDO from the Discover Identity ACK.
    pub header: IdHeaderVdo,
    /// Passive / active / VPD, from the header's UFP product type.
    pub kind: CableKind,
    /// Present iff `kind == Passive`.
    pub passive: Option<PassiveCableVdo>,
    /// Present iff `kind == Active`.
    pub active: Option<ActiveCableVdo1>,
}

/// Cable-plug kind, from the ID Header UFP product type
/// (USB-PD §6.4.4.3.1.1, table 6-30).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum CableKind {
    #[default]
    Unknown,
    Passive,
    Active,
    Vpd,
}

/// A cable's full decoded identity: near plug (SOP') plus, when the
/// near plug is active and reports SOP'' support, the far plug
/// (SOP''). `far == None` means no far identity was obtained
/// (passive near plug, no SOP'' support, or far timeout/NAK).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CableIdentity {
    pub near: PlugIdentity,
    pub far: Option<PlugIdentity>,
}

/// Discovery state machine state (mirrors the DP module's
/// `DpAltStep::Advanced(AltModeState)` shape: the step outcome
/// carries the state it advanced to).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CableState {
    /// No live contract (or not started yet).
    NotReady,
    /// Discover Identity sent to SOP'; awaiting its ACK.
    DiscoveringPrime { polls: u32 },
    /// Near plug is active with SOP'' support; Discover Identity
    /// sent to SOP''; awaiting its ACK.
    DiscoveringDoublePrime { polls: u32 },
    /// Identity obtained (near, plus far when applicable).
    Done,
    /// No e-marker answered within the poll budget.
    NotPresent,
    /// Protocol violation (unexpected product type, short response,
    /// NAK to the near-plug request).
    Failed,
    /// The TCPC cannot transmit to SOP* targets.
    Unsupported,
}

/// Outcome of one [`CableDiscoveryPort::step`] call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CableStep {
    /// Nothing to do — wait for the port to reach a contract.
    NotReady,
    /// State machine advanced (frame sent / response consumed).
    Advanced(CableState),
    /// Discovery finished with an identity.
    Done(CableIdentity),
    /// No e-marker answered.
    NotPresent,
    /// Protocol violation; terminal for this attach.
    Failed,
    /// TCPC has no SOP* path; terminal for this attach.
    Unsupported,
}

/// Errors from [`CableDiscoveryPort::step`].
#[derive(Debug)]
pub enum CableError {
    /// Capability revoked; the task exits.
    AuthorityRevoked,
    /// TCPC bus/transmit error; the task sleeps and retries.
    Tcpc(TcpcError),
}

impl From<CapError> for CableError {
    fn from(_: CapError) -> Self {
        CableError::AuthorityRevoked
    }
}

impl From<TcpcError> for CableError {
    fn from(e: TcpcError) -> Self {
        CableError::Tcpc(e)
    }
}

/// One cable-discovery driver bound to a TCPM port.
#[derive(Debug)]
pub struct CableDiscoveryPort {
    port: Arc<TcpmPort>,
    /// Stable USB-C connector id, shared with the DP port for the
    /// same receptacle so [`settled_for`] can gate DP discovery.
    connector: ConnectorId,
    state: IrqSafeSpinLock<CableState>,
    identity: IrqSafeSpinLock<Option<CableIdentity>>,
    next_msg_id: AtomicU8,
}

impl CableDiscoveryPort {
    pub fn new(port: Arc<TcpmPort>, connector: ConnectorId) -> Self {
        Self {
            port,
            connector,
            state: IrqSafeSpinLock::new(CableState::NotReady),
            identity: IrqSafeSpinLock::new(None),
            next_msg_id: AtomicU8::new(0),
        }
    }

    pub fn connector(&self) -> ConnectorId {
        self.connector
    }

    pub fn port_label(&self) -> &str {
        &self.port.label
    }

    /// The decoded cable identity, if discovery completed.
    pub fn cable_identity(&self) -> Option<CableIdentity> {
        *self.identity.lock()
    }

    /// True once discovery has reached a terminal state for this
    /// attach (Done / NotPresent / Failed / Unsupported). Used to
    /// gate DP discovery; see the module docs.
    pub fn settled(&self) -> bool {
        matches!(
            *self.state.lock(),
            CableState::Done
                | CableState::NotPresent
                | CableState::Failed
                | CableState::Unsupported
        )
    }

    fn next_msg_id(&self) -> u8 {
        self.next_msg_id.fetch_add(1, Ordering::AcqRel) & 0x7
    }

    fn reset_locked(&self, state: &mut CableState) {
        *state = CableState::NotReady;
        *self.identity.lock() = None;
    }

    /// Message-header roles for an outgoing cable-plug frame, from
    /// the port's live state. Source side follows the source
    /// engine's data role; sink side is UFP (the sink engine
    /// hardcodes UFP, matching the common sink-as-device case).
    /// A DR-swapped sink-DFP would send UFP role bits here; the
    /// plug does not gate Discover Identity on role bits, so this
    /// is cosmetic until the sink engine tracks data role.
    fn header_roles(&self) -> (DataRole, PowerRole) {
        match self.port.state() {
            PortState::AttachedSrc => (
                if self.port.source().is_dfp() {
                    DataRole::Dfp
                } else {
                    DataRole::Ufp
                },
                PowerRole::Source,
            ),
            _ => (DataRole::Ufp, PowerRole::Sink),
        }
    }

    /// Send a Discover Identity VDM to a cable-plug target.
    fn transmit_discover(&self, target: SopTarget) -> Result<(), CableError> {
        let (data_role, power_role) = self.header_roles();
        let h = Header::data(
            DataMsg::VendorDefined,
            data_role,
            power_role,
            SpecRev::R3_0,
            self.next_msg_id(),
            1,
        );
        let frame = narf_usbpd::message::encode_message(h, &[discover_identity_vdm_header()]);
        self.port.tcpc().transmit_sop(target, &frame)?;
        Ok(())
    }

    /// Decode one Discover Identity ACK's data objects into a plug
    /// identity. `objs[0]` is the ID Header; `objs[1]` (when
    /// present) is the cable VDO. Returns `None` when the objects
    /// are not a well-formed cable-plug identity.
    fn decode_plug(objs: &[u32]) -> Option<PlugIdentity> {
        let header = IdHeaderVdo::decode(*objs.first()?);
        match header.ufp_product_type {
            CABLE_PLUG_TYPE_PASSIVE_CABLE => Some(PlugIdentity {
                header,
                kind: CableKind::Passive,
                passive: Some(PassiveCableVdo::decode(*objs.get(1)?)),
                active: None,
            }),
            CABLE_PLUG_TYPE_ACTIVE_CABLE => Some(PlugIdentity {
                header,
                kind: CableKind::Active,
                passive: None,
                active: Some(ActiveCableVdo1::decode(*objs.get(1)?)),
            }),
            CABLE_PLUG_TYPE_VPD => Some(PlugIdentity {
                header,
                kind: CableKind::Vpd,
                passive: None,
                active: None,
            }),
            _ => None,
        }
    }

    /// Drive one discovery step. Returns the step outcome; the
    /// discovery task paces re-calls (25 ms while awaiting,
    /// 100 ms once settled).
    pub fn step(&self, cap: &Cap<UsbPd, Grant>) -> Result<CableStep, CableError> {
        cap.invoke(NoopOp)?;
        // Detach discipline (#1193 mirror): a dropped contract
        // clears any previous attach's identity, so a re-attach
        // re-discovers instead of serving stale cable data.
        if !self.port.contract_live() {
            let mut state = self.state.lock();
            if *state != CableState::NotReady {
                self.reset_locked(&mut state);
            }
            return Ok(CableStep::NotReady);
        }

        let mut state = self.state.lock();
        match *state {
            CableState::NotReady => {
                // transmit_sop returns Unsupported on TCPCs with no
                // SOP* path (e.g. TPS65987); that is terminal for
                // this attach, not a retryable error.
                match self.transmit_discover(SopTarget::SopPrime) {
                    Ok(()) => {
                        *state = CableState::DiscoveringPrime { polls: 0 };
                        Ok(CableStep::Advanced(*state))
                    }
                    Err(CableError::Tcpc(TcpcError::Unsupported)) => {
                        *state = CableState::Unsupported;
                        Ok(CableStep::Unsupported)
                    }
                    Err(e) => Err(e),
                }
            }
            CableState::DiscoveringPrime { polls } => {
                match self.await_ack(SopTarget::SopPrime, polls)? {
                    AwaitOutcome::StillWaiting { polls } => {
                        *state = CableState::DiscoveringPrime { polls };
                        Ok(CableStep::Advanced(*state))
                    }
                    AwaitOutcome::Timeout => {
                        *state = CableState::NotPresent;
                        Ok(CableStep::NotPresent)
                    }
                    AwaitOutcome::Nak => {
                        *state = CableState::Failed;
                        Ok(CableStep::Failed)
                    }
                    AwaitOutcome::Ack(objs) => {
                        let Some(near) = Self::decode_plug(&objs) else {
                            *state = CableState::Failed;
                            return Ok(CableStep::Failed);
                        };
                        // Chain into SOP'' only for an active near
                        // plug that reports SOP'' support.
                        let needs_double_prime = near.kind == CableKind::Active
                            && near
                                .active
                                .map(|v| v.sop_double_prime_supported)
                                .unwrap_or(false);
                        if !needs_double_prime {
                            let identity = CableIdentity { near, far: None };
                            *self.identity.lock() = Some(identity);
                            *state = CableState::Done;
                            return Ok(CableStep::Done(identity));
                        }
                        match self.transmit_discover(SopTarget::SopDoublePrime) {
                            Ok(()) => {
                                // Stash the near identity BEFORE
                                // entering DiscoveringDoublePrime:
                                // its Ack/Timeout/Nak branches read
                                // the stored identity to complete
                                // (partial or full) Done.
                                *self.identity.lock() = Some(CableIdentity { near, far: None });
                                *state = CableState::DiscoveringDoublePrime { polls: 0 };
                                Ok(CableStep::Advanced(*state))
                            }
                            Err(CableError::Tcpc(TcpcError::Unsupported)) => {
                                // Near identity is still valid; far
                                // discovery just cannot run here.
                                let identity = CableIdentity { near, far: None };
                                *self.identity.lock() = Some(identity);
                                *state = CableState::Done;
                                Ok(CableStep::Done(identity))
                            }
                            Err(e) => Err(e),
                        }
                    }
                }
            }
            CableState::DiscoveringDoublePrime { polls } => {
                // The near identity was stashed on entry to this
                // state by the prime branch (it is Some by
                // construction); the branches below read it from
                // the identity lock.
                match self.await_ack(SopTarget::SopDoublePrime, polls)? {
                    AwaitOutcome::StillWaiting { polls } => {
                        *state = CableState::DiscoveringDoublePrime { polls };
                        Ok(CableStep::Advanced(*state))
                    }
                    // Far timeout / NAK still yields the valid near
                    // identity (partial result, documented).
                    AwaitOutcome::Timeout | AwaitOutcome::Nak => {
                        let Some(identity) = *self.identity.lock() else {
                            *state = CableState::Failed;
                            return Ok(CableStep::Failed);
                        };
                        *state = CableState::Done;
                        Ok(CableStep::Done(identity))
                    }
                    AwaitOutcome::Ack(objs) => {
                        let Some(far) = Self::decode_plug(&objs) else {
                            *state = CableState::Failed;
                            return Ok(CableStep::Failed);
                        };
                        let Some(mut identity) = *self.identity.lock() else {
                            *state = CableState::Failed;
                            return Ok(CableStep::Failed);
                        };
                        identity.far = Some(far);
                        *self.identity.lock() = Some(identity);
                        *state = CableState::Done;
                        Ok(CableStep::Done(identity))
                    }
                }
            }
            CableState::Done => Ok(CableStep::Done(self.identity.lock().unwrap_or_default())),
            CableState::NotPresent => Ok(CableStep::NotPresent),
            CableState::Failed => Ok(CableStep::Failed),
            CableState::Unsupported => Ok(CableStep::Unsupported),
        }
    }

    /// One RX poll while awaiting a Discover Identity ACK from
    /// `target`. Returns the ACK's objects, or why waiting ended.
    /// Non-ACK traffic (wrong SOP target, non-VDM frames, VDMs for
    /// other commands) is ignored, not consumed as an answer —
    /// except that a popped SOP-target VDM is gone from the FIFO
    /// (see the module docs on RX arbitration; the DP gate bounds
    /// this window to before DP discovery starts).
    fn await_ack(&self, target: SopTarget, polls: u32) -> Result<AwaitOutcome, CableError> {
        let (got_target, bytes) = match self.port.tcpc().receive_sop() {
            Ok(v) => v,
            Err(TcpcError::NoMessage) => {
                let polls = polls + 1;
                if polls > MAX_RESPONSE_POLLS {
                    return Ok(AwaitOutcome::Timeout);
                }
                return Ok(AwaitOutcome::StillWaiting { polls });
            }
            Err(e) => return Err(CableError::Tcpc(e)),
        };
        // Wrong-target traffic is not our answer. (It is already
        // popped; the DP gate means no DP response should be in
        // flight during cable discovery.)
        if got_target != target {
            return Ok(AwaitOutcome::StillWaiting { polls });
        }
        let Some((_h, objs)) = narf_usbpd::message::decode_message(&bytes) else {
            return Ok(AwaitOutcome::StillWaiting { polls });
        };
        if _h.msg_type != DataMsg::VendorDefined as u8 || objs.is_empty() {
            return Ok(AwaitOutcome::StillWaiting { polls });
        }
        let vh = VdmHeader::decode(objs[0]);
        if vh.svid != SVID_PD
            || vh.vdm_type as u8 != 1
            || vh.command != VdmCommand::DiscoverIdentity as u8
        {
            return Ok(AwaitOutcome::StillWaiting { polls });
        }
        match vh.command_type {
            CommandType::Ack => Ok(AwaitOutcome::Ack(objs)),
            CommandType::Nak => Ok(AwaitOutcome::Nak),
            // Busy: keep waiting; the plug will answer or we time out.
            _ => Ok(AwaitOutcome::StillWaiting { polls }),
        }
    }
}

/// Outcome of one [`CableDiscoveryPort::await_ack`] poll.
enum AwaitOutcome {
    StillWaiting { polls: u32 },
    Timeout,
    Nak,
    Ack(Vec<u32>),
}

pub static CABLE_DISCOVERY_PORTS: IrqSafeSpinLock<Vec<Arc<CableDiscoveryPort>>> =
    IrqSafeSpinLock::new(Vec::new());

pub fn register_port(p: Arc<CableDiscoveryPort>) {
    CABLE_DISCOVERY_PORTS.lock().push(p);
}

pub fn registered_ports() -> Vec<Arc<CableDiscoveryPort>> {
    CABLE_DISCOVERY_PORTS.lock().clone()
}

/// True when the cable port for `connector` has settled for this
/// attach — or when no cable port is registered for it (defensive:
/// DP discovery must never block on a missing cable task).
pub fn settled_for(connector: ConnectorId) -> bool {
    let ports = CABLE_DISCOVERY_PORTS.lock();
    match ports
        .iter()
        .find(|p| p.connector.as_u32() == connector.as_u32())
    {
        Some(p) => p.settled(),
        None => true,
    }
}

/// Test-only registry reset.
#[doc(hidden)]
pub fn __test_reset() {
    CABLE_DISCOVERY_PORTS.lock().clear();
}

/// Spawn an async task that drives one cable-discovery port to a
/// terminal state and keeps it fresh across detach + re-attach.
/// Cadence mirrors the DP discovery task: 25 ms while awaiting,
/// yield on advance, 100 ms once settled.
pub fn spawn_discovery_task(p: Arc<CableDiscoveryPort>, label: String) {
    use core::fmt::Write as _;
    use narf_time::{Deadline, SleepUntil};
    narf_scheduler::spawn(async move {
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        loop {
            match p.step(&cap) {
                Ok(CableStep::Done(id)) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  cable: {} identity: {:?} far: {}",
                        label,
                        id.near.kind,
                        id.far.is_some()
                    );
                    SleepUntil::new(Deadline::after_ms(100).as_instant()).await;
                }
                Ok(CableStep::NotPresent) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  cable: {} no e-marker answered",
                        label
                    );
                    SleepUntil::new(Deadline::after_ms(100).as_instant()).await;
                }
                Ok(CableStep::Failed) => {
                    let _ = writeln!(narf_console::Writer, "  cable: {} discovery failed", label);
                    SleepUntil::new(Deadline::after_ms(100).as_instant()).await;
                }
                Ok(CableStep::Unsupported) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  cable: {} TCPC has no SOP* path",
                        label
                    );
                    SleepUntil::new(Deadline::after_ms(100).as_instant()).await;
                }
                Ok(CableStep::NotReady) => {
                    SleepUntil::new(Deadline::after_ms(25).as_instant()).await;
                }
                Ok(CableStep::Advanced(_)) => {
                    narf_scheduler::yield_now().await;
                }
                Err(e) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  cable: {} step failed: {:?}",
                        label,
                        e
                    );
                    if matches!(e, CableError::AuthorityRevoked) {
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
    use narf_usbpd::vdm::build_discover_identity_req;

    use crate::policy::{SinkPolicy, SourcePolicy};
    use crate::tcpm::TcpmPort;

    /// Fake TCPC with SOP*-aware scripted RX. `tx_sop` records the
    /// target so tests pin the framing, not just the payload.
    #[derive(Debug)]
    struct FakeChip {
        cc: IrqSafeSpinLock<CcStatus>,
        tx: IrqSafeSpinLock<Vec<(SopTarget, Vec<u8>)>>,
        rx: IrqSafeSpinLock<Vec<(SopTarget, Vec<u8>)>>,
        role: IrqSafeSpinLock<PortRole>,
        /// When set, `transmit_sop` fails with Unsupported (models a
        /// firmware-mediated TCPC with no SOP* path).
        no_sop: bool,
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
                no_sop: false,
            }
        }

        fn enqueue_rx_sop(&self, target: SopTarget, b: Vec<u8>) {
            self.rx.lock().push((target, b));
        }

        fn tx_targets(&self) -> Vec<SopTarget> {
            self.tx.lock().iter().map(|(t, _)| *t).collect()
        }

        fn last_tx(&self) -> Option<(SopTarget, Vec<u8>)> {
            self.tx.lock().last().cloned()
        }
    }

    impl Tcpc for FakeChip {
        fn name(&self) -> &'static str {
            "fake-cable"
        }

        fn set_role(&self, r: PortRole) -> Result<(), TcpcError> {
            *self.role.lock() = r;
            Ok(())
        }

        fn cc_status(&self) -> Result<CcStatus, TcpcError> {
            Ok(*self.cc.lock())
        }

        fn transmit(&self, m: &[u8]) -> Result<(), TcpcError> {
            self.tx.lock().push((SopTarget::Sop, m.to_vec()));
            Ok(())
        }

        fn transmit_sop(&self, target: SopTarget, m: &[u8]) -> Result<(), TcpcError> {
            if self.no_sop && target != SopTarget::Sop {
                return Err(TcpcError::Unsupported);
            }
            self.tx.lock().push((target, m.to_vec()));
            Ok(())
        }

        fn receive(&self) -> Result<Vec<u8>, TcpcError> {
            let mut q = self.rx.lock();
            if q.is_empty() {
                return Err(TcpcError::NoMessage);
            }
            Ok(q.remove(0).1)
        }

        fn receive_sop(&self) -> Result<(SopTarget, Vec<u8>), TcpcError> {
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
            DataRole::Dfp,
            PowerRole::Source,
            SpecRev::R3_0,
            0,
            vdos.len() as u8,
        );
        narf_usbpd::message::encode_message(h, vdos)
    }

    /// Drive a TcpmPort all the way to a live sink contract (same
    /// harness shape as the DP tests).
    fn drive_to_sink_ready(chip: &Arc<FakeChip>, port: &TcpmPort, cap: &Cap<UsbPd, Grant>) {
        let _ = port.step(cap).unwrap();
        for _ in 0..6 {
            let _ = port.step(cap).unwrap();
        }
        let pdos = [SourcePdo::Fixed {
            voltage_mv: 5000,
            max_current_ma: 3000,
        }];
        let h = Header::data(
            DataMsg::SourceCapabilities,
            DataRole::Dfp,
            PowerRole::Source,
            SpecRev::R3_0,
            0,
            1,
        );
        chip.enqueue_rx_sop(
            SopTarget::Sop,
            narf_usbpd::message::encode_message(h, &[pdos[0].encode()]),
        );
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
        chip.enqueue_rx_sop(
            SopTarget::Sop,
            narf_usbpd::message::encode_message(accept, &[]),
        );
        let _ = port.step(cap).unwrap();
        let ps_rdy = Header::control(
            CtrlMsg::PsRdy,
            DataRole::Dfp,
            PowerRole::Source,
            SpecRev::R3_0,
            2,
        );
        chip.enqueue_rx_sop(
            SopTarget::Sop,
            narf_usbpd::message::encode_message(ps_rdy, &[]),
        );
        let _ = port.step(cap).unwrap();
    }

    /// Discover Identity ACK objects for a passive cable fixture:
    /// ID Header (passive plug, 5 A, Gen2) + Passive Cable VDO.
    fn passive_ack_objects() -> Vec<u32> {
        let id = IdHeaderVdo {
            usb_host_capable: false,
            usb_device_capable: false,
            ufp_product_type: CABLE_PLUG_TYPE_PASSIVE_CABLE,
            modal_operation: false,
            dfp_product_type: 0,
            connector_type: 3,
            vendor_id: 0x1234,
        };
        let vdo = PassiveCableVdo {
            hw_version: 1,
            firmware_version: 2,
            vdo_version: 0,
            plug_type: 0,
            epr_mode_capable: false,
            cable_latency: 2,
            cable_termination: 1,
            max_vbus_voltage: 1,
            vbus_current: 2,     // 5 A
            usb_ss_signaling: 2, // Gen2
        };
        alloc::vec![id.encode(), vdo.encode()]
    }

    /// Discover Identity ACK objects for an active cable fixture
    /// with SOP'' support: ID Header (active plug) + Active VDO 1.
    fn active_ack_objects() -> Vec<u32> {
        let id = IdHeaderVdo {
            usb_host_capable: false,
            usb_device_capable: false,
            ufp_product_type: CABLE_PLUG_TYPE_ACTIVE_CABLE,
            modal_operation: false,
            dfp_product_type: 0,
            connector_type: 3,
            vendor_id: 0x5678,
        };
        let vdo = ActiveCableVdo1 {
            hw_version: 1,
            firmware_version: 1,
            vdo_version: 0,
            plug_type: 0,
            epr_mode_capable: false,
            cable_latency: 1,
            cable_termination: 0,
            max_vbus_voltage: 1,
            sbu_supported: false,
            sbu_type: 0,
            vbus_current: 1,
            vbus_through_cable: true,
            sop_double_prime_supported: true,
            usb_ss_signaling: 3, // Gen3
        };
        alloc::vec![id.encode(), vdo.encode()]
    }

    /// Wrap ACK objects in a structured Discover Identity ACK VDM
    /// frame addressed from `target`.
    fn ack_frame(target: SopTarget, objs: &[u32]) -> (SopTarget, Vec<u8>) {
        let mut vdos = alloc::vec![VdmHeader {
            svid: SVID_PD,
            vdm_type: narf_usbpd::vdm::VdmType::Structured,
            version: narf_usbpd::vdm::StructuredVdmVersion::V2_0,
            object_position: 0,
            command_type: CommandType::Ack,
            command: VdmCommand::DiscoverIdentity as u8,
        }
        .encode()];
        vdos.extend_from_slice(objs);
        (target, vdm_frame(&vdos))
    }

    fn smoke_cable_step_returns_not_ready_before_contract() -> TestResult {
        let chip = Arc::new(FakeChip::new());
        let port = Arc::new(TcpmPort::new(
            chip,
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("cable-test"),
        ));
        let cable = CableDiscoveryPort::new(port, ConnectorId::from_index(0));
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        match cable.step(&cap) {
            Ok(CableStep::NotReady) => TestResult::Pass,
            _ => TestResult::Fail("step should return NotReady before contract is live"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/cable-discovery",
        smoke_cable_step_returns_not_ready_before_contract
    );

    fn smoke_cable_passive_walk_to_done() -> TestResult {
        // The two independent Discover Identity builders must agree
        // (spec-fixture cross-check): sop_prime's header builder and
        // the vdm builder produce the same DWORD.
        if discover_identity_vdm_header() != build_discover_identity_req()[0] {
            return TestResult::Fail("sop_prime and vdm Discover Identity headers disagree");
        }
        let chip = Arc::new(FakeChip::new());
        let port = Arc::new(TcpmPort::new(
            chip.clone(),
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("cable-passive"),
        ));
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        drive_to_sink_ready(&chip, &port, &cap);
        if !port.contract_live() {
            return TestResult::Fail("test harness failed to drive the port to Ready");
        }
        let cable = CableDiscoveryPort::new(port, ConnectorId::from_index(0));
        // Kickoff: one SOP' Discover Identity transmit, pinned
        // byte-for-byte against the spec-shaped frame.
        match cable.step(&cap) {
            Ok(CableStep::Advanced(_)) => {}
            _ => return TestResult::Fail("kickoff should advance to DiscoveringPrime"),
        }
        let Some((target, tx)) = chip.last_tx() else {
            return TestResult::Fail("kickoff transmitted nothing");
        };
        if target != SopTarget::SopPrime {
            return TestResult::Fail("kickoff must transmit to SOP', not SOP");
        }
        let h = Header::data(
            DataMsg::VendorDefined,
            DataRole::Ufp,
            PowerRole::Sink,
            SpecRev::R3_0,
            0,
            1,
        );
        let expected = narf_usbpd::message::encode_message(h, &[discover_identity_vdm_header()]);
        if tx != expected {
            return TestResult::Fail("SOP' Discover Identity frame bytes differ from spec frame");
        }
        // SOP' ACK with the passive cable identity.
        let (t, f) = ack_frame(SopTarget::SopPrime, &passive_ack_objects());
        chip.enqueue_rx_sop(t, f);
        match cable.step(&cap) {
            Ok(CableStep::Done(id)) => {
                if id.near.kind != CableKind::Passive || id.far.is_some() {
                    return TestResult::Fail("passive identity mismatch");
                }
                let Some(p) = id.near.passive else {
                    return TestResult::Fail("passive VDO missing");
                };
                if p.vbus_current != 2 || p.usb_ss_signaling != 2 || p.cable_latency != 2 {
                    return TestResult::Fail("passive VDO fields misdecoded");
                }
                if id.near.header.vendor_id != 0x1234 {
                    return TestResult::Fail("ID Header vendor id misdecoded");
                }
            }
            _ => return TestResult::Fail("SOP' ACK should land Done with passive identity"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/cable-discovery",
        smoke_cable_passive_walk_to_done
    );

    fn smoke_cable_active_chains_to_double_prime() -> TestResult {
        let chip = Arc::new(FakeChip::new());
        let port = Arc::new(TcpmPort::new(
            chip.clone(),
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("cable-active"),
        ));
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        drive_to_sink_ready(&chip, &port, &cap);
        let cable = CableDiscoveryPort::new(port, ConnectorId::from_index(0));
        let _ = cable.step(&cap).unwrap(); // kickoff SOP'
        let (t, f) = ack_frame(SopTarget::SopPrime, &active_ack_objects());
        chip.enqueue_rx_sop(t, f);
        // Active near plug with SOP'' support: chains to SOP''.
        match cable.step(&cap) {
            Ok(CableStep::Advanced(_)) => {}
            _ => return TestResult::Fail("active SOP' ACK should chain to SOP''"),
        }
        let targets = chip.tx_targets();
        if targets.last() != Some(&SopTarget::SopDoublePrime) {
            return TestResult::Fail("second transmit must target SOP''");
        }
        // Far plug answers (passive far plug).
        let (t, f) = ack_frame(SopTarget::SopDoublePrime, &passive_ack_objects());
        chip.enqueue_rx_sop(t, f);
        match cable.step(&cap) {
            Ok(CableStep::Done(id)) => {
                if id.near.kind != CableKind::Active || id.far.is_none() {
                    return TestResult::Fail("active+far identity mismatch");
                }
                if id.far.map(|f| f.kind) != Some(CableKind::Passive) {
                    return TestResult::Fail("far plug kind mismatch");
                }
            }
            _ => return TestResult::Fail("SOP'' ACK should land Done with near+far"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/cable-discovery",
        smoke_cable_active_chains_to_double_prime
    );

    fn smoke_cable_wrong_target_ignored_and_timeout() -> TestResult {
        let chip = Arc::new(FakeChip::new());
        let port = Arc::new(TcpmPort::new(
            chip.clone(),
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("cable-mask"),
        ));
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        drive_to_sink_ready(&chip, &port, &cap);
        let cable = CableDiscoveryPort::new(port, ConnectorId::from_index(0));
        let _ = cable.step(&cap).unwrap(); // kickoff SOP'
                                           // A SOP-target ACK must NOT satisfy a SOP' wait (masking
                                           // defeat: the DP task's partner identity is not cable data).
        let (t, f) = ack_frame(SopTarget::Sop, &passive_ack_objects());
        chip.enqueue_rx_sop(t, f);
        match cable.step(&cap) {
            Ok(CableStep::Advanced(_)) => {}
            _ => return TestResult::Fail("wrong-target ACK must be ignored, not Done"),
        }
        if cable.cable_identity().is_some() {
            return TestResult::Fail("wrong-target ACK must not store an identity");
        }
        // No further answers: poll to the budget → NotPresent, and
        // no retransmit storm (exactly one transmit total).
        for _ in 0..=MAX_RESPONSE_POLLS {
            let _ = cable.step(&cap).unwrap();
        }
        match cable.step(&cap) {
            Ok(CableStep::NotPresent) => {}
            _ => return TestResult::Fail("poll budget exhaustion should land NotPresent"),
        }
        if chip.tx_targets().len() != 1 {
            return TestResult::Fail("no-response path must not retransmit");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/cable-discovery",
        smoke_cable_wrong_target_ignored_and_timeout
    );

    fn smoke_cable_detach_clears_identity() -> TestResult {
        let chip = Arc::new(FakeChip::new());
        let port = Arc::new(TcpmPort::new(
            chip.clone(),
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("cable-detach"),
        ));
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        drive_to_sink_ready(&chip, &port, &cap);
        let cable = CableDiscoveryPort::new(port.clone(), ConnectorId::from_index(0));
        let _ = cable.step(&cap).unwrap();
        let (t, f) = ack_frame(SopTarget::SopPrime, &passive_ack_objects());
        chip.enqueue_rx_sop(t, f);
        if !matches!(cable.step(&cap), Ok(CableStep::Done(_))) {
            return TestResult::Fail("setup walk should land Done");
        }
        // Detach: open CC pins, step the port, then step cable.
        *chip.cc.lock() = CcStatus {
            cc1: CcState::Open,
            cc2: CcState::Open,
        };
        let _ = port.step(&cap).unwrap();
        match cable.step(&cap) {
            Ok(CableStep::NotReady) => {}
            _ => return TestResult::Fail("detach should return cable to NotReady"),
        }
        if cable.cable_identity().is_some() {
            return TestResult::Fail("detach must clear the stored identity");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/cable-discovery",
        smoke_cable_detach_clears_identity
    );

    fn smoke_cable_unsupported_tcpc_settles() -> TestResult {
        let mut chip = FakeChip::new();
        chip.no_sop = true;
        let chip = Arc::new(chip);
        let port = Arc::new(TcpmPort::new(
            chip.clone(),
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("cable-unsup"),
        ));
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        drive_to_sink_ready(&chip, &port, &cap);
        let cable = CableDiscoveryPort::new(port, ConnectorId::from_index(0));
        match cable.step(&cap) {
            Ok(CableStep::Unsupported) => TestResult::Pass,
            _ => TestResult::Fail("SOP*-less TCPC should settle Unsupported, not error"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/cable-discovery",
        smoke_cable_unsupported_tcpc_settles
    );
}
