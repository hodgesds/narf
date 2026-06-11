//! TCPM port driver — Stage 1 source-role state machine + Type-C
//! attach/detach plumbing.
//!
//! The pure spec types + sink-role engine live in `narf_usbpd::tcpm`
//! (see `usbpd/src/tcpm.rs`); this module sits on top with:
//!
//! - A *source* policy engine matching USB-PD 3.1 §8.3.3.2:
//!   `SRC_STARTUP → SRC_DISCOVERY → SRC_SEND_CAPABILITIES →
//!    SRC_NEGOTIATE_CAPABILITY → SRC_TRANSITION_SUPPLY → SRC_READY`.
//! - The Type-C side states `ATTACHED_SRC` / `ATTACHED_SNK` /
//!   `ERROR_RECOVERY` that wrap *both* power-role engines so a per-
//!   port task can run one of them depending on CC orientation.
//! - The async port-driving task that picks sink or source based on
//!   what the chip reports, and announces contracts on the console.
//!
//! Linux's `drivers/usb/typec/tcpm/tcpm.c::tcpm_state_machine` packs
//! all of this into one giant `switch`; we split source/sink because
//! the existing sink-only engine already lives upstream in
//! `narf_usbpd::tcpm`, and Stage-1 only needs us to add source + a
//! Type-C-level dispatcher.
//!
//! References (public, non-GPL):
//! - **USB Power Delivery 3.1 v1.8** (USB-IF), §8.3.3.2 (Source PE),
//!   §8.3.3.3 (Sink PE), §4.5.2 (Type-C attach), §8.3.3.6 (Hard
//!   Reset), §8.3.3.7 (Error Recovery).
//!   <https://www.usb.org/document-library/usb-power-delivery>
//! - **USB Type-C Cable and Connector Spec 2.2** (USB-IF), §4.5.2.2
//!   (Source.Attached / Sink.Attached substates).
//!   <https://www.usb.org/document-library/usb-type-c-cable-and-connector-specification-revision-22>

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};

use narf_capabilities::{Cap, CapError, Grant, NoopOp};
use narf_lib::sync::IrqSafeSpinLock;
use narf_usbpd::message::{
    decode_message, encode_message, BistDataObject, BistMode, CtrlMsg, DataMsg, DataRole, FixedRdo,
    Header, PowerRole, ProgrammableRdo, SourcePdo, SpecRev,
};
use narf_usbpd::tcpc::{CcState, CcStatus, PortRole, Tcpc, TcpcError};
use narf_usbpd::tcpm::{Contract, SinkPort, SinkState, StepOutcome};
use narf_usbpd::UsbPd;

use crate::policy::{RequestDecision, SinkPolicy, SourcePolicy};

// ── Source Policy Engine state (§8.3.3.2) ──────────────────────────

/// Source Policy Engine state — direct one-to-one with §8.3.3.2 plus
/// the PR_Swap (§8.3.3.4) sub-states.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SourceState {
    /// SRC_STARTUP: just attached as Source. Reset protocol layer +
    /// move to Discovery.
    Startup = 0,
    /// SRC_DISCOVERY: wait tTypeCSendSourceCap before issuing first
    /// Source_Capabilities (§6.6.1). We model this as a single step
    /// that runs from a kernel timer; the wait is handled by the
    /// driving task.
    Discovery = 1,
    /// SRC_SEND_CAPABILITIES: emit Source_Capabilities on the wire.
    SendCapabilities = 2,
    /// SRC_NEGOTIATE_CAPABILITY: have Source_Capabilities outstanding,
    /// waiting for the sink's Request.
    NegotiateCapability = 3,
    /// SRC_TRANSITION_SUPPLY: Request accepted; we've sent Accept and
    /// are waiting for the rail to settle before sending PS_RDY.
    TransitionSupply = 4,
    /// SRC_READY: contract live, sink can pull power.
    Ready = 5,
    /// SRC_HARD_RESET: send Hard Reset on the wire, then re-Startup.
    HardReset = 6,
    /// PR_Swap_Send (§8.3.3.4.4): we initiated the swap; PR_Swap sent.
    PrSwapSend = 7,
    /// PR_Swap_Wait_Reply: waiting for Accept/Reject/Wait.
    PrSwapWaitReply = 8,
    /// PR_Swap_Transition_to_off (§8.3.3.4.6): Accept landed, turning
    /// off Vbus before sending PS_RDY.
    PrSwapTransitionToOff = 9,
    /// PR_Swap_Source_off: Vbus off; we wait for the partner's PS_RDY
    /// then complete the swap.
    PrSwapSourceOff = 10,
    /// DR_Swap_Send: DR_Swap sent, waiting for reply.
    DrSwapSend = 11,
    /// DR_Swap_Wait_Reply.
    DrSwapWaitReply = 12,
    /// DR_Swap_Change: Accept landed; data role just flipped.
    DrSwapChange = 13,
    /// VConn_Swap_Send.
    VconnSwapSend = 14,
    /// VConn_Swap_Wait_Reply.
    VconnSwapWaitReply = 15,
    /// VConn_Swap_Start: we are now the VConn supplier.
    VconnSwapStart = 16,
    /// VConn_Swap_Turn_off: we just released VConn.
    VconnSwapTurnOff = 17,
    /// BIST_Carrier_Mode (§6.4.3.1): a BIST data message was received;
    /// we acknowledge entry. The chip-level emit is left to the TCPC.
    BistCarrierMode = 18,
}

/// Error from the source state machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SourceError {
    AuthorityRevoked,
    Tcpc(TcpcError),
    /// Sink sent a malformed Request RDO or out-of-range position.
    Protocol,
}

impl From<CapError> for SourceError {
    fn from(_: CapError) -> Self {
        SourceError::AuthorityRevoked
    }
}

impl From<TcpcError> for SourceError {
    fn from(e: TcpcError) -> Self {
        SourceError::Tcpc(e)
    }
}

/// One outcome of `SourcePort::step`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SourceStepOutcome {
    /// Moved forward; call again soon.
    Advanced(SourceState),
    /// Waiting on an external event (RX message, timer).
    Idle(SourceState),
    /// Contract live — sink is now drawing power.
    Ready { contract: Contract },
    /// PR_Swap completed — this port is now a *sink*. The driving
    /// `TcpmPort` flips its underlying engine and re-arms.
    RoleSwappedToSink,
    /// DR_Swap completed — data role flipped.
    DataRoleSwapped { now_dfp: bool },
    /// VConn_Swap completed — our VConn-supplier flag flipped.
    VconnSwapped { now_supplying: bool },
    /// BIST Carrier Mode 2 entered — partner asked us to emit the BIST
    /// pattern; the TCPC chip is responsible for actually generating
    /// it. We park here until the partner clears with a Hard Reset.
    BistEntered,
}

/// Source-role policy engine running on top of a TCPC.
#[derive(Debug)]
pub struct SourcePort {
    tcpc: Arc<dyn Tcpc>,
    policy: IrqSafeSpinLock<SourcePolicy>,
    state: AtomicU8,
    /// Most recently received Request RDO (the sink's pick), kept so
    /// `TransitionSupply` knows which PDO to lock in.
    pending_request: IrqSafeSpinLock<Option<FixedRdo>>,
    /// Same, for PPS — held when the sink picked an APDO position.
    pending_pps_request: IrqSafeSpinLock<Option<ProgrammableRdo>>,
    next_msg_id: AtomicU8,
    contract: IrqSafeSpinLock<Option<Contract>>,
    /// Current data role. Source-role typically starts DFP; flips on
    /// every successful DR_Swap. `true` = DFP, `false` = UFP.
    is_dfp: AtomicU8,
    /// Are we currently supplying VConn on the active CC pin? Sources
    /// default to supplying VConn (§4.5.4); flips on every successful
    /// VConn_Swap.
    is_vconn_supplier: AtomicU8,
}

impl SourcePort {
    pub fn new(tcpc: Arc<dyn Tcpc>, policy: SourcePolicy) -> Self {
        Self {
            tcpc,
            policy: IrqSafeSpinLock::new(policy),
            state: AtomicU8::new(SourceState::Startup as u8),
            pending_request: IrqSafeSpinLock::new(None),
            pending_pps_request: IrqSafeSpinLock::new(None),
            next_msg_id: AtomicU8::new(0),
            contract: IrqSafeSpinLock::new(None),
            is_dfp: AtomicU8::new(1),
            is_vconn_supplier: AtomicU8::new(1),
        }
    }

    pub fn state(&self) -> SourceState {
        let v = self.state.load(Ordering::Acquire);
        // Safety: we only ever store SourceState discriminants.
        unsafe { core::mem::transmute(v) }
    }

    pub fn contract(&self) -> Option<Contract> {
        *self.contract.lock()
    }

    /// True when this port is currently the DFP (Downstream-Facing
    /// Port = USB host). Flips on every successful DR_Swap.
    pub fn is_dfp(&self) -> bool {
        self.is_dfp.load(Ordering::Acquire) != 0
    }

    /// True when this port is currently supplying VConn on the
    /// active CC pin. Flips on every successful VConn_Swap.
    pub fn is_vconn_supplier(&self) -> bool {
        self.is_vconn_supplier.load(Ordering::Acquire) != 0
    }

    fn set_state(&self, s: SourceState) {
        self.state.store(s as u8, Ordering::Release);
    }

    fn data_role(&self) -> DataRole {
        if self.is_dfp() {
            DataRole::Dfp
        } else {
            DataRole::Ufp
        }
    }

    fn next_msg_id(&self) -> u8 {
        let v = self.next_msg_id.fetch_add(1, Ordering::AcqRel);
        v & 0x7
    }

    /// Externally request a PR_Swap. Only legal from `SRC_READY`.
    /// Returns false if the source is in another state.
    pub fn initiate_pr_swap(&self) -> bool {
        if self.state() != SourceState::Ready {
            return false;
        }
        self.set_state(SourceState::PrSwapSend);
        true
    }

    /// Externally request a DR_Swap. Only legal from `SRC_READY`.
    pub fn initiate_dr_swap(&self) -> bool {
        if self.state() != SourceState::Ready {
            return false;
        }
        self.set_state(SourceState::DrSwapSend);
        true
    }

    /// Externally request a VConn_Swap. Only legal from `SRC_READY`.
    pub fn initiate_vconn_swap(&self) -> bool {
        if self.state() != SourceState::Ready {
            return false;
        }
        self.set_state(SourceState::VconnSwapSend);
        true
    }

    /// Run one step. The driving task pumps this until it sees `Ready`
    /// or `Idle`.
    pub fn step(&self, cap: &Cap<UsbPd, Grant>) -> Result<SourceStepOutcome, SourceError> {
        cap.invoke(NoopOp)?;
        match self.state() {
            SourceState::Startup => {
                self.tcpc.set_role(PortRole::Source)?;
                self.next_msg_id.store(0, Ordering::Release);
                *self.pending_request.lock() = None;
                *self.pending_pps_request.lock() = None;
                *self.contract.lock() = None;
                self.is_dfp.store(1, Ordering::Release);
                self.is_vconn_supplier.store(1, Ordering::Release);
                self.set_state(SourceState::Discovery);
                Ok(SourceStepOutcome::Advanced(SourceState::Discovery))
            }
            SourceState::Discovery => {
                // §6.6.1 says the source waits tTypeCSendSourceCap
                // (≤ 200 ms) before its first Source_Capabilities,
                // but the wait is done by the driving task. The
                // step itself just advances to SendCapabilities.
                self.set_state(SourceState::SendCapabilities);
                Ok(SourceStepOutcome::Advanced(SourceState::SendCapabilities))
            }
            SourceState::SendCapabilities => self.step_send_capabilities(),
            SourceState::NegotiateCapability => self.step_negotiate(),
            SourceState::TransitionSupply => self.step_transition_supply(),
            SourceState::Ready => self.step_ready_or_handle_inbound(),
            SourceState::HardReset => {
                let _ = self.tcpc.hard_reset();
                self.set_state(SourceState::Startup);
                Ok(SourceStepOutcome::Advanced(SourceState::Startup))
            }
            SourceState::PrSwapSend => self.step_pr_swap_send(),
            SourceState::PrSwapWaitReply => self.step_pr_swap_wait_reply(),
            SourceState::PrSwapTransitionToOff => self.step_pr_swap_transition_to_off(),
            SourceState::PrSwapSourceOff => self.step_pr_swap_source_off(),
            SourceState::DrSwapSend => self.step_dr_swap_send(),
            SourceState::DrSwapWaitReply => self.step_dr_swap_wait_reply(),
            SourceState::DrSwapChange => self.step_dr_swap_change(),
            SourceState::VconnSwapSend => self.step_vconn_swap_send(),
            SourceState::VconnSwapWaitReply => self.step_vconn_swap_wait_reply(),
            SourceState::VconnSwapStart => self.step_vconn_swap_start(),
            SourceState::VconnSwapTurnOff => self.step_vconn_swap_turn_off(),
            SourceState::BistCarrierMode => {
                Ok(SourceStepOutcome::Idle(SourceState::BistCarrierMode))
            }
        }
    }

    fn step_send_capabilities(&self) -> Result<SourceStepOutcome, SourceError> {
        let pdos: Vec<SourcePdo> = self.policy.lock().pdos.clone();
        if pdos.is_empty() {
            // Empty source policy is a configuration bug — fail loud
            // by hopping into Hard Reset.
            self.set_state(SourceState::HardReset);
            return Err(SourceError::Protocol);
        }
        let h = Header::data(
            DataMsg::SourceCapabilities,
            self.data_role(),
            PowerRole::Source,
            SpecRev::R3_0,
            self.next_msg_id(),
            pdos.len() as u8,
        );
        let objs: Vec<u32> = pdos.iter().map(|p| p.encode()).collect();
        let frame = encode_message(h, &objs);
        self.tcpc.transmit(&frame)?;
        self.set_state(SourceState::NegotiateCapability);
        Ok(SourceStepOutcome::Advanced(
            SourceState::NegotiateCapability,
        ))
    }

    fn step_negotiate(&self) -> Result<SourceStepOutcome, SourceError> {
        // Wait for the sink to send a Request. We pull one message
        // per step; the driving task re-enters us on TCPC RX.
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => {
                return Ok(SourceStepOutcome::Idle(SourceState::NegotiateCapability))
            }
            Err(e) => return Err(SourceError::Tcpc(e)),
        };
        let (h, objs) = decode_message(&buf).ok_or(SourceError::Protocol)?;
        if h.num_data_objects == 0
            || DataMsg::from_u8(h.msg_type) != Some(DataMsg::Request)
            || objs.is_empty()
        {
            // Anything that isn't a Request is a protocol violation
            // here — bounce through HardReset.
            self.set_state(SourceState::HardReset);
            return Err(SourceError::Protocol);
        }
        // Pick the right RDO type by inspecting the targeted PDO.
        // Augmented PDOs use a Programmable RDO (§6.4.2.5); everything
        // else uses a Fixed RDO.
        let raw = objs[0];
        let position = ((raw >> 28) & 0x7) as u8;
        let pdo = self
            .policy
            .lock()
            .pdos
            .get(
                position
                    .checked_sub(1)
                    .map(|x| x as usize)
                    .unwrap_or(usize::MAX),
            )
            .copied();
        let is_pps = matches!(pdo, Some(SourcePdo::Augmented { .. }));
        let decision = if is_pps {
            let prdo = ProgrammableRdo::decode(raw);
            *self.pending_pps_request.lock() = Some(prdo);
            self.policy.lock().evaluate_programmable_request(&prdo)
        } else {
            let rdo = FixedRdo::decode(raw);
            *self.pending_request.lock() = Some(rdo);
            self.policy.lock().evaluate_request(&rdo)
        };
        let (reply_ctrl, next_state) = match decision {
            RequestDecision::Accept => (CtrlMsg::Accept, SourceState::TransitionSupply),
            RequestDecision::Wait => (CtrlMsg::Wait, SourceState::NegotiateCapability),
            RequestDecision::Reject => (CtrlMsg::Reject, SourceState::NegotiateCapability),
        };
        let h_reply = Header::control(
            reply_ctrl,
            self.data_role(),
            PowerRole::Source,
            SpecRev::R3_0,
            self.next_msg_id(),
        );
        let frame = encode_message(h_reply, &[]);
        self.tcpc.transmit(&frame)?;
        if !matches!(decision, RequestDecision::Accept) {
            // Drop the stashed request so a follow-up Negotiate
            // doesn't see stale data.
            *self.pending_request.lock() = None;
            *self.pending_pps_request.lock() = None;
        }
        self.set_state(next_state);
        Ok(SourceStepOutcome::Advanced(next_state))
    }

    fn step_transition_supply(&self) -> Result<SourceStepOutcome, SourceError> {
        // §8.3.3.2.5: after Accept, the source drives Vbus to the new
        // voltage and then sends PS_RDY. We don't drive a real rail —
        // emit PS_RDY immediately, and let the chip driver decide
        // how Vbus is actually steered.
        // PPS path first — if a Programmable RDO was stashed, the
        // contract is built from its requested voltage.
        let (object_position, voltage_mv, op_current_ma) =
            if let Some(prdo) = self.pending_pps_request.lock().take() {
                (prdo.object_position, prdo.voltage_mv, prdo.op_current_ma)
            } else {
                let pending = match self.pending_request.lock().take() {
                    Some(r) => r,
                    None => {
                        // We're in TransitionSupply without a stashed
                        // request — impossible unless the state
                        // machine was poked externally. Bounce.
                        self.set_state(SourceState::HardReset);
                        return Err(SourceError::Protocol);
                    }
                };
                let policy = self.policy.lock().clone();
                let pdo = policy
                    .pdos
                    .get(
                        pending
                            .object_position
                            .checked_sub(1)
                            .map(|x| x as usize)
                            .unwrap_or(usize::MAX),
                    )
                    .copied()
                    .ok_or(SourceError::Protocol)?;
                let voltage_mv = match pdo {
                    SourcePdo::Fixed { voltage_mv, .. } => voltage_mv,
                    SourcePdo::Variable { max_voltage_mv, .. } => max_voltage_mv,
                    SourcePdo::Augmented { max_voltage_mv, .. } => max_voltage_mv,
                    SourcePdo::Battery { max_voltage_mv, .. } => max_voltage_mv,
                };
                (pending.object_position, voltage_mv, pending.op_current_ma)
            };
        let h = Header::control(
            CtrlMsg::PsRdy,
            self.data_role(),
            PowerRole::Source,
            SpecRev::R3_0,
            self.next_msg_id(),
        );
        let frame = encode_message(h, &[]);
        self.tcpc.transmit(&frame)?;
        let contract = Contract {
            object_position,
            voltage_mv,
            op_current_ma,
        };
        *self.contract.lock() = Some(contract);
        self.set_state(SourceState::Ready);
        Ok(SourceStepOutcome::Ready { contract })
    }

    // ── Ready-state inbound handling ───────────────────────────────

    /// In `SRC_READY` the partner may send PR_Swap (more inbound
    /// messages are wired in subsequent Stage-2 commits). Drain at
    /// most one inbound message per step; if there's nothing we idle.
    fn step_ready_or_handle_inbound(&self) -> Result<SourceStepOutcome, SourceError> {
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => return Ok(SourceStepOutcome::Idle(SourceState::Ready)),
            Err(e) => return Err(SourceError::Tcpc(e)),
        };
        let (h, objs) = decode_message(&buf).ok_or(SourceError::Protocol)?;
        if h.num_data_objects > 0 {
            // BIST is the only inbound data message we handle in
            // Ready; anything else is a protocol violation.
            if DataMsg::from_u8(h.msg_type) == Some(DataMsg::Bist) && !objs.is_empty() {
                if let Some(bdo) = BistDataObject::decode(objs[0]) {
                    if matches!(bdo.mode, BistMode::CarrierMode2 | BistMode::TestData) {
                        // §6.4.3: the UUT enters BIST and parks here
                        // until the partner clears with a Hard Reset.
                        self.set_state(SourceState::BistCarrierMode);
                        return Ok(SourceStepOutcome::BistEntered);
                    }
                }
            }
            self.set_state(SourceState::HardReset);
            return Err(SourceError::Protocol);
        }
        match CtrlMsg::from_u8(h.msg_type) {
            Some(CtrlMsg::PrSwap) => self.handle_inbound_pr_swap(),
            Some(CtrlMsg::DrSwap) => self.handle_inbound_dr_swap(),
            Some(CtrlMsg::VconnSwap) => self.handle_inbound_vconn_swap(),
            Some(CtrlMsg::SoftReset) => {
                // §6.3.13: respond with Accept then restart from
                // Startup. The driving task observes the state hop.
                self.send_control(CtrlMsg::Accept)?;
                self.set_state(SourceState::Startup);
                Ok(SourceStepOutcome::Advanced(SourceState::Startup))
            }
            _ => Ok(SourceStepOutcome::Idle(SourceState::Ready)),
        }
    }

    fn send_control(&self, msg: CtrlMsg) -> Result<(), SourceError> {
        let h = Header::control(
            msg,
            self.data_role(),
            PowerRole::Source,
            SpecRev::R3_0,
            self.next_msg_id(),
        );
        let frame = encode_message(h, &[]);
        self.tcpc.transmit(&frame)?;
        Ok(())
    }

    // ── PR_Swap — initiated by us ──────────────────────────────────

    fn step_pr_swap_send(&self) -> Result<SourceStepOutcome, SourceError> {
        self.send_control(CtrlMsg::PrSwap)?;
        self.set_state(SourceState::PrSwapWaitReply);
        Ok(SourceStepOutcome::Advanced(SourceState::PrSwapWaitReply))
    }

    fn step_pr_swap_wait_reply(&self) -> Result<SourceStepOutcome, SourceError> {
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => {
                return Ok(SourceStepOutcome::Idle(SourceState::PrSwapWaitReply))
            }
            Err(e) => return Err(SourceError::Tcpc(e)),
        };
        let (h, _) = decode_message(&buf).ok_or(SourceError::Protocol)?;
        match CtrlMsg::from_u8(h.msg_type) {
            Some(CtrlMsg::Accept) => {
                self.set_state(SourceState::PrSwapTransitionToOff);
                Ok(SourceStepOutcome::Advanced(
                    SourceState::PrSwapTransitionToOff,
                ))
            }
            Some(CtrlMsg::Reject) | Some(CtrlMsg::Wait) => {
                // Partner declined; stay sourcing.
                self.set_state(SourceState::Ready);
                Ok(SourceStepOutcome::Advanced(SourceState::Ready))
            }
            _ => Err(SourceError::Protocol),
        }
    }

    fn step_pr_swap_transition_to_off(&self) -> Result<SourceStepOutcome, SourceError> {
        // §8.3.3.4.6: turn Vbus off (chip-managed) then send PS_RDY.
        // The TCPC trait doesn't expose a Vbus enable today — Stage 2
        // hands that to the chip-level driver. We emit PS_RDY so the
        // partner knows our rail is down.
        self.send_control(CtrlMsg::PsRdy)?;
        self.set_state(SourceState::PrSwapSourceOff);
        Ok(SourceStepOutcome::Advanced(SourceState::PrSwapSourceOff))
    }

    fn step_pr_swap_source_off(&self) -> Result<SourceStepOutcome, SourceError> {
        // Wait for the partner's PS_RDY (they have now turned *their*
        // rail on).
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => {
                return Ok(SourceStepOutcome::Idle(SourceState::PrSwapSourceOff))
            }
            Err(e) => return Err(SourceError::Tcpc(e)),
        };
        let (h, _) = decode_message(&buf).ok_or(SourceError::Protocol)?;
        if CtrlMsg::from_u8(h.msg_type) != Some(CtrlMsg::PsRdy) {
            return Err(SourceError::Protocol);
        }
        // Flip CC drive to Sink. The driving task will then re-enter
        // the engine as a sink.
        self.tcpc.set_role(PortRole::Sink)?;
        *self.contract.lock() = None;
        self.set_state(SourceState::Startup);
        Ok(SourceStepOutcome::RoleSwappedToSink)
    }

    fn handle_inbound_pr_swap(&self) -> Result<SourceStepOutcome, SourceError> {
        // §8.3.3.4.3: the responder evaluates policy and Accepts /
        // Rejects / Waits. On Accept the responder transitions Vbus
        // off and then becomes a sink — same path as initiated PR_Swap
        // from PrSwapTransitionToOff onward.
        let accept = self.policy.lock().accept_pr_swap;
        if accept {
            self.send_control(CtrlMsg::Accept)?;
            self.set_state(SourceState::PrSwapTransitionToOff);
            Ok(SourceStepOutcome::Advanced(
                SourceState::PrSwapTransitionToOff,
            ))
        } else {
            self.send_control(CtrlMsg::Reject)?;
            self.set_state(SourceState::Ready);
            Ok(SourceStepOutcome::Advanced(SourceState::Ready))
        }
    }

    // ── DR_Swap ────────────────────────────────────────────────────

    fn step_dr_swap_send(&self) -> Result<SourceStepOutcome, SourceError> {
        self.send_control(CtrlMsg::DrSwap)?;
        self.set_state(SourceState::DrSwapWaitReply);
        Ok(SourceStepOutcome::Advanced(SourceState::DrSwapWaitReply))
    }

    fn step_dr_swap_wait_reply(&self) -> Result<SourceStepOutcome, SourceError> {
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => {
                return Ok(SourceStepOutcome::Idle(SourceState::DrSwapWaitReply))
            }
            Err(e) => return Err(SourceError::Tcpc(e)),
        };
        let (h, _) = decode_message(&buf).ok_or(SourceError::Protocol)?;
        match CtrlMsg::from_u8(h.msg_type) {
            Some(CtrlMsg::Accept) => {
                self.set_state(SourceState::DrSwapChange);
                Ok(SourceStepOutcome::Advanced(SourceState::DrSwapChange))
            }
            Some(CtrlMsg::Reject) | Some(CtrlMsg::Wait) => {
                self.set_state(SourceState::Ready);
                Ok(SourceStepOutcome::Advanced(SourceState::Ready))
            }
            _ => Err(SourceError::Protocol),
        }
    }

    fn step_dr_swap_change(&self) -> Result<SourceStepOutcome, SourceError> {
        // §8.3.3.5.5: flip the data role and return to Ready.
        let now_dfp = !self.is_dfp();
        self.is_dfp
            .store(if now_dfp { 1 } else { 0 }, Ordering::Release);
        self.set_state(SourceState::Ready);
        Ok(SourceStepOutcome::DataRoleSwapped { now_dfp })
    }

    fn handle_inbound_dr_swap(&self) -> Result<SourceStepOutcome, SourceError> {
        let accept = self.policy.lock().accept_dr_swap;
        if accept {
            self.send_control(CtrlMsg::Accept)?;
            self.set_state(SourceState::DrSwapChange);
            Ok(SourceStepOutcome::Advanced(SourceState::DrSwapChange))
        } else {
            self.send_control(CtrlMsg::Reject)?;
            self.set_state(SourceState::Ready);
            Ok(SourceStepOutcome::Advanced(SourceState::Ready))
        }
    }

    // ── VConn_Swap ─────────────────────────────────────────────────

    fn step_vconn_swap_send(&self) -> Result<SourceStepOutcome, SourceError> {
        self.send_control(CtrlMsg::VconnSwap)?;
        self.set_state(SourceState::VconnSwapWaitReply);
        Ok(SourceStepOutcome::Advanced(SourceState::VconnSwapWaitReply))
    }

    fn step_vconn_swap_wait_reply(&self) -> Result<SourceStepOutcome, SourceError> {
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => {
                return Ok(SourceStepOutcome::Idle(SourceState::VconnSwapWaitReply))
            }
            Err(e) => return Err(SourceError::Tcpc(e)),
        };
        let (h, _) = decode_message(&buf).ok_or(SourceError::Protocol)?;
        match CtrlMsg::from_u8(h.msg_type) {
            Some(CtrlMsg::Accept) => {
                // §8.3.3.6.4: VConn-source goes to Turn_off; VConn-
                // sink goes to Start. We pick by our current state:
                // if we're already a supplier, we turn off; otherwise
                // we start.
                let next = if self.is_vconn_supplier() {
                    SourceState::VconnSwapTurnOff
                } else {
                    SourceState::VconnSwapStart
                };
                self.set_state(next);
                Ok(SourceStepOutcome::Advanced(next))
            }
            Some(CtrlMsg::Reject) | Some(CtrlMsg::Wait) => {
                self.set_state(SourceState::Ready);
                Ok(SourceStepOutcome::Advanced(SourceState::Ready))
            }
            _ => Err(SourceError::Protocol),
        }
    }

    fn step_vconn_swap_start(&self) -> Result<SourceStepOutcome, SourceError> {
        // We are now the VConn supplier; emit PS_RDY so the partner
        // can finish turning theirs off.
        self.send_control(CtrlMsg::PsRdy)?;
        self.is_vconn_supplier.store(1, Ordering::Release);
        self.set_state(SourceState::Ready);
        Ok(SourceStepOutcome::VconnSwapped {
            now_supplying: true,
        })
    }

    fn step_vconn_swap_turn_off(&self) -> Result<SourceStepOutcome, SourceError> {
        // Wait for partner's PS_RDY, then release VConn.
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => {
                return Ok(SourceStepOutcome::Idle(SourceState::VconnSwapTurnOff))
            }
            Err(e) => return Err(SourceError::Tcpc(e)),
        };
        let (h, _) = decode_message(&buf).ok_or(SourceError::Protocol)?;
        if CtrlMsg::from_u8(h.msg_type) != Some(CtrlMsg::PsRdy) {
            return Err(SourceError::Protocol);
        }
        self.is_vconn_supplier.store(0, Ordering::Release);
        self.set_state(SourceState::Ready);
        Ok(SourceStepOutcome::VconnSwapped {
            now_supplying: false,
        })
    }

    fn handle_inbound_vconn_swap(&self) -> Result<SourceStepOutcome, SourceError> {
        let accept = self.policy.lock().accept_vconn_swap;
        if accept {
            self.send_control(CtrlMsg::Accept)?;
            let next = if self.is_vconn_supplier() {
                SourceState::VconnSwapTurnOff
            } else {
                SourceState::VconnSwapStart
            };
            self.set_state(next);
            Ok(SourceStepOutcome::Advanced(next))
        } else {
            self.send_control(CtrlMsg::Reject)?;
            self.set_state(SourceState::Ready);
            Ok(SourceStepOutcome::Advanced(SourceState::Ready))
        }
    }
}

// ── Type-C-level attach/detach controller ──────────────────────────

/// Aggregate state for one port. Wraps both power-role engines and
/// adds the Type-C-side states from §4.5.2.2 (Source.Attached /
/// Sink.Attached) plus §8.3.3.7 ERROR_RECOVERY.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PortState {
    /// CC pins open: nothing connected.
    Unattached = 0,
    /// CC stayed asserted past tCCDebounce; partner present.
    AttachedSnk = 1,
    /// Same, but we are presenting Rp (we're the source).
    AttachedSrc = 2,
    /// §8.3.3.7: power-rail glitch detected; tear everything down to
    /// Unattached and restart.
    ErrorRecovery = 3,
    /// §6.4.3 BIST mode — the partner asked us to enter a Built-In
    /// Self-Test pattern. We acknowledge but don't drive the chip.
    Bist = 4,
}

/// Outcome from one Type-C-level step. The driving task uses the
/// underlying engine's outcome (sink or source) to pace polling.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PortStepOutcome {
    Idle(PortState),
    Advanced(PortState),
    SinkReady(Contract),
    SourceReady(Contract),
    /// We were asked to enter BIST; the caller can stay in `Bist`
    /// until the partner clears it.
    BistEntered,
    /// Power role just flipped — we were sourcing and are now a sink
    /// (or vice-versa, once Stage-2's sink-side PR_Swap lands).
    RoleSwapped(PortState),
    /// Data role just flipped — UFP/DFP toggled.
    DataRoleSwapped {
        now_dfp: bool,
    },
    /// VConn supplier just flipped.
    VconnSwapped {
        now_supplying: bool,
    },
}

/// Top-level port driver: owns one chip + both engines, picks which
/// to drive based on CC orientation.
#[derive(Debug)]
pub struct TcpmPort {
    tcpc: Arc<dyn Tcpc>,
    sink: Arc<SinkPort>,
    source: Arc<SourcePort>,
    state: AtomicU8,
    /// Stable label for diagnostics, e.g. `\_SB.I2CA@0x22`.
    pub label: String,
    /// True once we've successfully entered AttachedSnk or
    /// AttachedSrc once. Used by the Alt-Mode hook to decide whether
    /// the partner is ready for VDM.
    contract_announced: AtomicU8,
}

impl TcpmPort {
    pub fn new(
        tcpc: Arc<dyn Tcpc>,
        sink_policy: SinkPolicy,
        source_policy: SourcePolicy,
        label: String,
    ) -> Self {
        let _ = sink_policy; // sink policy lives in the engine via
                             // narf_usbpd's default; Stage-2 will
                             // make narf_usbpd::SinkPort policy-driven.
        let sink = Arc::new(SinkPort::new(tcpc.clone()));
        let source = Arc::new(SourcePort::new(tcpc.clone(), source_policy));
        Self {
            tcpc,
            sink,
            source,
            state: AtomicU8::new(PortState::Unattached as u8),
            label,
            contract_announced: AtomicU8::new(0),
        }
    }

    pub fn state(&self) -> PortState {
        let v = self.state.load(Ordering::Acquire);
        // Safety: only PortState discriminants are ever stored.
        unsafe { core::mem::transmute(v) }
    }

    fn set_state(&self, s: PortState) {
        self.state.store(s as u8, Ordering::Release);
    }

    pub fn sink(&self) -> &Arc<SinkPort> {
        &self.sink
    }

    pub fn source(&self) -> &Arc<SourcePort> {
        &self.source
    }

    pub fn tcpc(&self) -> &Arc<dyn Tcpc> {
        &self.tcpc
    }

    /// True iff we've reached a steady-state contract on either side.
    pub fn contract_live(&self) -> bool {
        matches!(
            (self.state(), self.sink.state(), self.source.state()),
            (PortState::AttachedSnk, SinkState::Ready, _)
                | (PortState::AttachedSrc, _, SourceState::Ready)
        )
    }

    /// Drive one step. Inspect the CC lines to pick sink vs source,
    /// then delegate to the appropriate engine.
    pub fn step(&self, cap: &Cap<UsbPd, Grant>) -> Result<PortStepOutcome, SourceError> {
        cap.invoke(NoopOp)?;
        // Quick CC check first — if the chip lost its partner mid-
        // negotiation we want to bail.
        let cc = self.tcpc.cc_status().map_err(SourceError::Tcpc)?;
        match self.state() {
            PortState::Unattached => {
                if !cc.attached() {
                    return Ok(PortStepOutcome::Idle(PortState::Unattached));
                }
                // Classify partner by what CC sees: if we see Rd the
                // partner is a sink (so we are source); if we see Rp
                // the partner is a source (so we are sink).
                let next = classify_role(&cc);
                self.set_state(next);
                self.contract_announced.store(0, Ordering::Release);
                Ok(PortStepOutcome::Advanced(next))
            }
            PortState::AttachedSnk => {
                if !cc.attached() {
                    self.set_state(PortState::Unattached);
                    return Ok(PortStepOutcome::Advanced(PortState::Unattached));
                }
                let outcome = self.sink.step(cap).map_err(map_sink_err)?;
                Ok(match outcome {
                    StepOutcome::Ready { contract } => PortStepOutcome::SinkReady(contract),
                    StepOutcome::Advanced(_) => PortStepOutcome::Advanced(PortState::AttachedSnk),
                    StepOutcome::Idle(_) => PortStepOutcome::Idle(PortState::AttachedSnk),
                })
            }
            PortState::AttachedSrc => {
                if !cc.attached() {
                    self.set_state(PortState::Unattached);
                    return Ok(PortStepOutcome::Advanced(PortState::Unattached));
                }
                let outcome = self.source.step(cap)?;
                Ok(match outcome {
                    SourceStepOutcome::Ready { contract } => PortStepOutcome::SourceReady(contract),
                    SourceStepOutcome::Advanced(_) => {
                        PortStepOutcome::Advanced(PortState::AttachedSrc)
                    }
                    SourceStepOutcome::Idle(_) => PortStepOutcome::Idle(PortState::AttachedSrc),
                    SourceStepOutcome::RoleSwappedToSink => {
                        // The source completed a PR_Swap and is now
                        // logically a sink. Move the port-level state
                        // to AttachedSnk and let the sink engine pick
                        // up from Unattached on the next step.
                        self.set_state(PortState::AttachedSnk);
                        PortStepOutcome::RoleSwapped(PortState::AttachedSnk)
                    }
                    SourceStepOutcome::DataRoleSwapped { now_dfp } => {
                        PortStepOutcome::DataRoleSwapped { now_dfp }
                    }
                    SourceStepOutcome::VconnSwapped { now_supplying } => {
                        PortStepOutcome::VconnSwapped { now_supplying }
                    }
                    SourceStepOutcome::BistEntered => {
                        self.set_state(PortState::Bist);
                        PortStepOutcome::BistEntered
                    }
                })
            }
            PortState::ErrorRecovery => {
                // §8.3.3.7: drop the rail and re-enter Unattached.
                let _ = self.tcpc.hard_reset();
                self.set_state(PortState::Unattached);
                Ok(PortStepOutcome::Advanced(PortState::Unattached))
            }
            PortState::Bist => Ok(PortStepOutcome::Idle(PortState::Bist)),
        }
    }

    /// Force the port into ERROR_RECOVERY. Called by upper layers
    /// when an out-of-band fault is detected (over-current, Vbus
    /// glitch, etc.).
    pub fn enter_error_recovery(&self) {
        self.set_state(PortState::ErrorRecovery);
    }

    /// Hop into BIST mode (test pattern). Partner clears this with a
    /// Hard Reset.
    pub fn enter_bist(&self) {
        self.set_state(PortState::Bist);
    }

    /// Ask the source engine to initiate a PR_Swap. Only legal while
    /// the port is `AttachedSrc` with the source in `SRC_READY`.
    pub fn initiate_pr_swap(&self) -> bool {
        if !matches!(self.state(), PortState::AttachedSrc) {
            return false;
        }
        self.source.initiate_pr_swap()
    }

    /// Ask the source engine to initiate a DR_Swap.
    pub fn initiate_dr_swap(&self) -> bool {
        if !matches!(self.state(), PortState::AttachedSrc) {
            return false;
        }
        self.source.initiate_dr_swap()
    }

    /// Ask the source engine to initiate a VConn_Swap.
    pub fn initiate_vconn_swap(&self) -> bool {
        if !matches!(self.state(), PortState::AttachedSrc) {
            return false;
        }
        self.source.initiate_vconn_swap()
    }
}

fn classify_role(cc: &CcStatus) -> PortState {
    // Partner pulls down with Rd → we're the source (we see Rd on
    // whichever CC pin the partner connected to).
    let sees_rd = matches!(cc.cc1, CcState::Rd) || matches!(cc.cc2, CcState::Rd);
    if sees_rd {
        PortState::AttachedSrc
    } else {
        PortState::AttachedSnk
    }
}

fn map_sink_err(e: narf_usbpd::tcpm::SinkError) -> SourceError {
    match e {
        narf_usbpd::tcpm::SinkError::AuthorityRevoked => SourceError::AuthorityRevoked,
        narf_usbpd::tcpm::SinkError::Tcpc(t) => SourceError::Tcpc(t),
        _ => SourceError::Protocol,
    }
}

// ── Registry ───────────────────────────────────────────────────────

/// Global registry of bound TCPM ports. Populated by
/// [`crate::register_initcalls`]; consumed by Alt-Mode + (future)
/// power-policy code.
pub static TCPM_PORTS: IrqSafeSpinLock<Vec<Arc<TcpmPort>>> = IrqSafeSpinLock::new(Vec::new());

pub fn register_port(port: Arc<TcpmPort>) {
    TCPM_PORTS.lock().push(port);
}

pub fn registered_ports() -> Vec<Arc<TcpmPort>> {
    TCPM_PORTS.lock().clone()
}

/// Test-only registry reset.
#[doc(hidden)]
pub fn __test_reset() {
    TCPM_PORTS.lock().clear();
}

// ── Smoke tests ────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_usbpd::message::{
        BistDataObject, BistMode, CtrlMsg, DataMsg, DataRole, FixedRdo, Header, PowerRole,
        ProgrammableRdo, SpecRev,
    };
    use narf_usbpd::tcpc::{CcState, CcStatus, PortRole, Tcpc, TcpcError};

    #[derive(Debug)]
    struct FakeChip {
        role: IrqSafeSpinLock<PortRole>,
        cc: IrqSafeSpinLock<CcStatus>,
        tx: IrqSafeSpinLock<Vec<Vec<u8>>>,
        rx: IrqSafeSpinLock<Vec<Vec<u8>>>,
    }

    impl FakeChip {
        fn new(cc: CcStatus) -> Self {
            Self {
                role: IrqSafeSpinLock::new(PortRole::Drp),
                cc: IrqSafeSpinLock::new(cc),
                tx: IrqSafeSpinLock::new(Vec::new()),
                rx: IrqSafeSpinLock::new(Vec::new()),
            }
        }
        fn enqueue_rx(&self, b: Vec<u8>) {
            self.rx.lock().push(b);
        }
        fn sent(&self) -> Vec<Vec<u8>> {
            self.tx.lock().clone()
        }
        fn set_cc(&self, cc1: CcState, cc2: CcState) {
            *self.cc.lock() = CcStatus { cc1, cc2 };
        }
    }
    impl Tcpc for FakeChip {
        fn name(&self) -> &'static str {
            "fake"
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

    fn request_frame(position: u8, current_ma: u32, message_id: u8) -> Vec<u8> {
        let h = Header::data(
            DataMsg::Request,
            DataRole::Ufp,
            PowerRole::Sink,
            SpecRev::R3_0,
            message_id,
            1,
        );
        let rdo = FixedRdo {
            object_position: position,
            op_current_ma: current_ma,
            max_op_current_ma: current_ma,
            give_back: false,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
        };
        encode_message(h, &[rdo.encode()])
    }

    fn smoke_source_state_machine_reaches_ready() -> TestResult {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Rd,
            cc2: CcState::Open,
        }));
        let policy = SourcePolicy::default();
        let port = SourcePort::new(chip.clone(), policy);
        let cap = narf_usbpd::bootstrap_usbpd_authority();

        // Startup → Discovery
        let _ = port.step(&cap).unwrap();
        if port.state() != SourceState::Discovery {
            return TestResult::Fail("Startup didn't advance to Discovery");
        }
        // Discovery → SendCapabilities
        let _ = port.step(&cap).unwrap();
        // SendCapabilities → NegotiateCapability (transmits caps)
        let _ = port.step(&cap).unwrap();
        if port.state() != SourceState::NegotiateCapability {
            return TestResult::Fail("did not advance to NegotiateCapability");
        }
        let sent = chip.sent();
        if sent.len() != 1 {
            return TestResult::Fail("Source did not transmit exactly one Source_Capabilities");
        }
        let (h, objs) = decode_message(&sent[0]).expect("decode caps");
        if DataMsg::from_u8(h.msg_type) != Some(DataMsg::SourceCapabilities) {
            return TestResult::Fail("first transmit wasn't Source_Capabilities");
        }
        if objs.len() != 1 {
            return TestResult::Fail("default policy should advertise exactly one PDO");
        }

        // Sink sends Request for PDO #1 @ 1.5 A.
        chip.enqueue_rx(request_frame(1, 1500, 0));
        // NegotiateCapability → TransitionSupply (sends Accept)
        let _ = port.step(&cap).unwrap();
        if port.state() != SourceState::TransitionSupply {
            return TestResult::Fail("Accept path didn't advance to TransitionSupply");
        }
        // TransitionSupply → Ready (sends PS_RDY)
        let outcome = port.step(&cap).unwrap();
        let contract = match outcome {
            SourceStepOutcome::Ready { contract } => contract,
            _ => return TestResult::Fail("TransitionSupply should produce Ready"),
        };
        if contract.voltage_mv != 5000 || contract.op_current_ma != 1500 {
            return TestResult::Fail("contract didn't lock 5V/1.5A");
        }
        if port.state() != SourceState::Ready {
            return TestResult::Fail("state didn't advance to Ready");
        }
        // Confirm last two sent frames were Accept then PS_RDY.
        let sent = chip.sent();
        if sent.len() != 3 {
            return TestResult::Fail("expected 3 TX (caps, Accept, PS_RDY)");
        }
        let (h1, _) = decode_message(&sent[1]).expect("decode");
        let (h2, _) = decode_message(&sent[2]).expect("decode");
        if CtrlMsg::from_u8(h1.msg_type) != Some(CtrlMsg::Accept) {
            return TestResult::Fail("frame #2 was not Accept");
        }
        if CtrlMsg::from_u8(h2.msg_type) != Some(CtrlMsg::PsRdy) {
            return TestResult::Fail("frame #3 was not PS_RDY");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_source_state_machine_reaches_ready
    );

    fn smoke_source_rejects_over_budget_request() -> TestResult {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Rd,
            cc2: CcState::Open,
        }));
        // Default source advertises 5 V / 3 A.
        let port = SourcePort::new(chip.clone(), SourcePolicy::default());
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        // Walk to NegotiateCapability.
        for _ in 0..3 {
            let _ = port.step(&cap).unwrap();
        }
        // Sink asks for 5 A — over budget.
        chip.enqueue_rx(request_frame(1, 5000, 0));
        let _ = port.step(&cap).unwrap();
        if port.state() != SourceState::NegotiateCapability {
            return TestResult::Fail("Reject path should stay in NegotiateCapability");
        }
        let sent = chip.sent();
        // sent[0] = caps; sent[1] = Reject.
        let (h_rej, _) = decode_message(&sent[1]).expect("decode");
        if CtrlMsg::from_u8(h_rej.msg_type) != Some(CtrlMsg::Reject) {
            return TestResult::Fail("over-budget request should produce Reject");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_source_rejects_over_budget_request
    );

    fn smoke_tcpmport_classifies_source_when_sees_rd() -> TestResult {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Rd,
            cc2: CcState::Open,
        }));
        let port = TcpmPort::new(
            chip,
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("test"),
        );
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        let _ = port.step(&cap).unwrap();
        if port.state() != PortState::AttachedSrc {
            return TestResult::Fail("seeing Rd on CC1 should classify as AttachedSrc");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_tcpmport_classifies_source_when_sees_rd
    );

    fn smoke_tcpmport_classifies_sink_when_sees_rp() -> TestResult {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Rp3A0,
            cc2: CcState::Open,
        }));
        let port = TcpmPort::new(
            chip,
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("test"),
        );
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        let _ = port.step(&cap).unwrap();
        if port.state() != PortState::AttachedSnk {
            return TestResult::Fail("seeing Rp on CC1 should classify as AttachedSnk");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_tcpmport_classifies_sink_when_sees_rp
    );

    fn smoke_tcpmport_detach_drops_to_unattached() -> TestResult {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Rd,
            cc2: CcState::Open,
        }));
        let port = TcpmPort::new(
            chip.clone(),
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("test"),
        );
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        // Get to AttachedSrc.
        let _ = port.step(&cap).unwrap();
        // Now simulate detach.
        chip.set_cc(CcState::Open, CcState::Open);
        let _ = port.step(&cap).unwrap();
        if port.state() != PortState::Unattached {
            return TestResult::Fail("detach should drop to Unattached");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_tcpmport_detach_drops_to_unattached
    );

    fn smoke_tcpmport_error_recovery_resets_to_unattached() -> TestResult {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Rd,
            cc2: CcState::Open,
        }));
        let port = TcpmPort::new(
            chip,
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("test"),
        );
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        port.enter_error_recovery();
        let _ = port.step(&cap).unwrap();
        if port.state() != PortState::Unattached {
            return TestResult::Fail("ErrorRecovery should reset to Unattached");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_tcpmport_error_recovery_resets_to_unattached
    );

    fn smoke_tcpmport_bist_blocks_engine_step() -> TestResult {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Rp3A0,
            cc2: CcState::Open,
        }));
        let port = TcpmPort::new(
            chip,
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("test"),
        );
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        port.enter_bist();
        let outcome = port.step(&cap).unwrap();
        match outcome {
            PortStepOutcome::Idle(PortState::Bist) => TestResult::Pass,
            _ => TestResult::Fail("BIST should idle the port"),
        }
    }
    kernel_test_in!("drivers/usbpd/tcpm", smoke_tcpmport_bist_blocks_engine_step);

    fn smoke_tcpmport_cap_revocation_blocks_step() -> TestResult {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Rd,
            cc2: CcState::Open,
        }));
        let port = TcpmPort::new(
            chip,
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("test"),
        );
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        cap.revoke();
        match port.step(&cap) {
            Err(SourceError::AuthorityRevoked) => TestResult::Pass,
            _ => TestResult::Fail("step accepted a revoked cap"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_tcpmport_cap_revocation_blocks_step
    );

    fn smoke_tcpm_port_registry_round_trip() -> TestResult {
        super::__test_reset();
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Open,
            cc2: CcState::Open,
        }));
        let port = Arc::new(TcpmPort::new(
            chip,
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("reg-test"),
        ));
        super::register_port(port);
        let ports = super::registered_ports();
        if ports.len() != 1 {
            return TestResult::Fail("registry didn't capture the port");
        }
        super::__test_reset();
        if !super::registered_ports().is_empty() {
            return TestResult::Fail("__test_reset didn't drain the registry");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usbpd/tcpm", smoke_tcpm_port_registry_round_trip);

    // ── Helpers shared across Stage-2 swap/BIST tests ─────────────

    /// Build a partner-originated Control message frame (the "wire" a
    /// FakeChip would deliver to our SourcePort on `receive()`).
    fn partner_ctrl_frame(msg: CtrlMsg) -> Vec<u8> {
        let h = Header::control(msg, DataRole::Ufp, PowerRole::Sink, SpecRev::R3_0, 0);
        encode_message(h, &[])
    }

    /// Pump steps until the source reaches `SRC_READY` or `n` steps
    /// are consumed. Returns true if Ready was reached.
    fn drive_to_ready(
        port: &SourcePort,
        chip: &FakeChip,
        cap: &Cap<UsbPd, Grant>,
        n: usize,
    ) -> bool {
        for _ in 0..n {
            if port.state() == SourceState::Ready {
                return true;
            }
            if port.state() == SourceState::NegotiateCapability {
                chip.enqueue_rx(request_frame(1, 1500, 0));
            }
            let _ = port.step(cap).unwrap();
        }
        port.state() == SourceState::Ready
    }

    fn fresh_source_port() -> (Arc<FakeChip>, SourcePort) {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Rd,
            cc2: CcState::Open,
        }));
        let port = SourcePort::new(chip.clone(), SourcePolicy::default());
        (chip, port)
    }

    // ── PR_Swap ───────────────────────────────────────────────────

    fn smoke_pr_swap_initiated_accept_path() -> TestResult {
        let (chip, port) = fresh_source_port();
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        if !drive_to_ready(&port, &chip, &cap, 8) {
            return TestResult::Fail("did not reach SRC_READY");
        }
        if !port.initiate_pr_swap() {
            return TestResult::Fail("initiate_pr_swap rejected from Ready");
        }
        let _ = port.step(&cap).unwrap(); // PrSwapSend → emit
        if port.state() != SourceState::PrSwapWaitReply {
            return TestResult::Fail("PrSwapSend should advance to WaitReply");
        }
        let sent = chip.sent();
        let (h, _) = decode_message(sent.last().unwrap()).unwrap();
        if CtrlMsg::from_u8(h.msg_type) != Some(CtrlMsg::PrSwap) {
            return TestResult::Fail("last sent frame should be PrSwap");
        }
        chip.enqueue_rx(partner_ctrl_frame(CtrlMsg::Accept));
        let _ = port.step(&cap).unwrap();
        if port.state() != SourceState::PrSwapTransitionToOff {
            return TestResult::Fail("Accept should advance to TransitionToOff");
        }
        let _ = port.step(&cap).unwrap(); // PS_RDY emitted
        if port.state() != SourceState::PrSwapSourceOff {
            return TestResult::Fail("TransitionToOff should advance to SourceOff");
        }
        chip.enqueue_rx(partner_ctrl_frame(CtrlMsg::PsRdy));
        let outcome = port.step(&cap).unwrap();
        match outcome {
            SourceStepOutcome::RoleSwappedToSink => TestResult::Pass,
            _ => TestResult::Fail("expected RoleSwappedToSink"),
        }
    }
    kernel_test_in!("drivers/usbpd/tcpm", smoke_pr_swap_initiated_accept_path);

    fn smoke_pr_swap_initiated_reject_returns_to_ready() -> TestResult {
        let (chip, port) = fresh_source_port();
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        let _ = drive_to_ready(&port, &chip, &cap, 8);
        port.initiate_pr_swap();
        let _ = port.step(&cap).unwrap();
        chip.enqueue_rx(partner_ctrl_frame(CtrlMsg::Reject));
        let _ = port.step(&cap).unwrap();
        if port.state() != SourceState::Ready {
            return TestResult::Fail("Reject should return to Ready");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_pr_swap_initiated_reject_returns_to_ready
    );

    fn smoke_pr_swap_inbound_accepted_when_policy_on() -> TestResult {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Rd,
            cc2: CcState::Open,
        }));
        let mut policy = SourcePolicy::default();
        policy.accept_pr_swap = true;
        let port = SourcePort::new(chip.clone(), policy);
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        let _ = drive_to_ready(&port, &chip, &cap, 8);
        chip.enqueue_rx(partner_ctrl_frame(CtrlMsg::PrSwap));
        let _ = port.step(&cap).unwrap();
        if port.state() != SourceState::PrSwapTransitionToOff {
            return TestResult::Fail("inbound PR_Swap with accept should reach TransitionToOff");
        }
        let sent = chip.sent();
        let (h, _) = decode_message(sent.last().unwrap()).unwrap();
        if CtrlMsg::from_u8(h.msg_type) != Some(CtrlMsg::Accept) {
            return TestResult::Fail("accept_pr_swap=true should send Accept");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_pr_swap_inbound_accepted_when_policy_on
    );

    fn smoke_pr_swap_inbound_rejected_by_default() -> TestResult {
        let (chip, port) = fresh_source_port();
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        let _ = drive_to_ready(&port, &chip, &cap, 8);
        chip.enqueue_rx(partner_ctrl_frame(CtrlMsg::PrSwap));
        let _ = port.step(&cap).unwrap();
        let sent = chip.sent();
        let (h, _) = decode_message(sent.last().unwrap()).unwrap();
        if CtrlMsg::from_u8(h.msg_type) != Some(CtrlMsg::Reject) {
            return TestResult::Fail("default policy should Reject PR_Swap");
        }
        if port.state() != SourceState::Ready {
            return TestResult::Fail("Reject should stay in Ready");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_pr_swap_inbound_rejected_by_default
    );

    fn smoke_pr_swap_initiate_blocked_outside_ready() -> TestResult {
        let (_chip, port) = fresh_source_port();
        if port.initiate_pr_swap() {
            return TestResult::Fail("PR_Swap should refuse from Startup");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_pr_swap_initiate_blocked_outside_ready
    );

    fn smoke_tcpmport_pr_swap_blocked_when_not_src() -> TestResult {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Open,
            cc2: CcState::Open,
        }));
        let port = TcpmPort::new(
            chip,
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("test"),
        );
        if port.initiate_pr_swap() {
            return TestResult::Fail("PR_Swap should refuse from Unattached");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_tcpmport_pr_swap_blocked_when_not_src
    );

    // ── DR_Swap ───────────────────────────────────────────────────

    fn smoke_dr_swap_initiated_accept_flips_data_role() -> TestResult {
        let (chip, port) = fresh_source_port();
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        let _ = drive_to_ready(&port, &chip, &cap, 8);
        let starting_dfp = port.is_dfp();
        port.initiate_dr_swap();
        let _ = port.step(&cap).unwrap(); // send
        let sent = chip.sent();
        let (h, _) = decode_message(sent.last().unwrap()).unwrap();
        if CtrlMsg::from_u8(h.msg_type) != Some(CtrlMsg::DrSwap) {
            return TestResult::Fail("first DR_Swap step should send DrSwap");
        }
        chip.enqueue_rx(partner_ctrl_frame(CtrlMsg::Accept));
        let _ = port.step(&cap).unwrap();
        let outcome = port.step(&cap).unwrap();
        match outcome {
            SourceStepOutcome::DataRoleSwapped { now_dfp } => {
                if now_dfp == starting_dfp {
                    return TestResult::Fail("data role did not flip");
                }
                if port.is_dfp() == starting_dfp {
                    return TestResult::Fail("is_dfp() did not update");
                }
                TestResult::Pass
            }
            _ => TestResult::Fail("expected DataRoleSwapped outcome"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_dr_swap_initiated_accept_flips_data_role
    );

    fn smoke_dr_swap_inbound_rejected_by_default() -> TestResult {
        let (chip, port) = fresh_source_port();
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        let _ = drive_to_ready(&port, &chip, &cap, 8);
        chip.enqueue_rx(partner_ctrl_frame(CtrlMsg::DrSwap));
        let _ = port.step(&cap).unwrap();
        let sent = chip.sent();
        let (h, _) = decode_message(sent.last().unwrap()).unwrap();
        if CtrlMsg::from_u8(h.msg_type) != Some(CtrlMsg::Reject) {
            return TestResult::Fail("default policy should Reject DR_Swap");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_dr_swap_inbound_rejected_by_default
    );

    fn smoke_dr_swap_inbound_accept_flips_when_policy_on() -> TestResult {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Rd,
            cc2: CcState::Open,
        }));
        let mut policy = SourcePolicy::default();
        policy.accept_dr_swap = true;
        let port = SourcePort::new(chip.clone(), policy);
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        let _ = drive_to_ready(&port, &chip, &cap, 8);
        let starting_dfp = port.is_dfp();
        chip.enqueue_rx(partner_ctrl_frame(CtrlMsg::DrSwap));
        let _ = port.step(&cap).unwrap();
        if port.state() != SourceState::DrSwapChange {
            return TestResult::Fail("accept_dr_swap=true should reach DrSwapChange");
        }
        let _ = port.step(&cap).unwrap();
        if port.is_dfp() == starting_dfp {
            return TestResult::Fail("data role did not flip after inbound DR_Swap");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_dr_swap_inbound_accept_flips_when_policy_on
    );

    // ── VConn_Swap ────────────────────────────────────────────────

    fn smoke_vconn_swap_initiated_supplier_releases() -> TestResult {
        let (chip, port) = fresh_source_port();
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        let _ = drive_to_ready(&port, &chip, &cap, 8);
        if !port.is_vconn_supplier() {
            return TestResult::Fail("source should default to VConn supplier");
        }
        port.initiate_vconn_swap();
        let _ = port.step(&cap).unwrap();
        let sent = chip.sent();
        let (h, _) = decode_message(sent.last().unwrap()).unwrap();
        if CtrlMsg::from_u8(h.msg_type) != Some(CtrlMsg::VconnSwap) {
            return TestResult::Fail("first step should emit VconnSwap");
        }
        chip.enqueue_rx(partner_ctrl_frame(CtrlMsg::Accept));
        let _ = port.step(&cap).unwrap();
        if port.state() != SourceState::VconnSwapTurnOff {
            return TestResult::Fail("supplier should transition to TurnOff");
        }
        chip.enqueue_rx(partner_ctrl_frame(CtrlMsg::PsRdy));
        let outcome = port.step(&cap).unwrap();
        match outcome {
            SourceStepOutcome::VconnSwapped {
                now_supplying: false,
            } => {
                if port.is_vconn_supplier() {
                    return TestResult::Fail("is_vconn_supplier should be false");
                }
                TestResult::Pass
            }
            _ => TestResult::Fail("expected VconnSwapped { now_supplying: false }"),
        }
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_vconn_swap_initiated_supplier_releases
    );

    fn smoke_vconn_swap_inbound_rejected_by_default() -> TestResult {
        let (chip, port) = fresh_source_port();
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        let _ = drive_to_ready(&port, &chip, &cap, 8);
        chip.enqueue_rx(partner_ctrl_frame(CtrlMsg::VconnSwap));
        let _ = port.step(&cap).unwrap();
        let sent = chip.sent();
        let (h, _) = decode_message(sent.last().unwrap()).unwrap();
        if CtrlMsg::from_u8(h.msg_type) != Some(CtrlMsg::Reject) {
            return TestResult::Fail("default policy should Reject VConn_Swap");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_vconn_swap_inbound_rejected_by_default
    );

    // ── PPS ───────────────────────────────────────────────────────

    fn partner_data_frame(msg: DataMsg, objs: &[u32]) -> Vec<u8> {
        let h = Header::data(
            msg,
            DataRole::Ufp,
            PowerRole::Sink,
            SpecRev::R3_0,
            0,
            objs.len() as u8,
        );
        encode_message(h, objs)
    }

    fn smoke_pps_source_accepts_programmable_request() -> TestResult {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Rd,
            cc2: CcState::Open,
        }));
        let policy = SourcePolicy::from_pdos(alloc::vec![
            SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 3000,
            },
            SourcePdo::Augmented {
                max_voltage_mv: 11000,
                min_voltage_mv: 3300,
                max_current_ma: 3000,
            },
        ]);
        let port = SourcePort::new(chip.clone(), policy);
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        for _ in 0..3 {
            let _ = port.step(&cap).unwrap();
        }
        let prdo = ProgrammableRdo {
            object_position: 2,
            voltage_mv: 9000,
            op_current_ma: 2000,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
        };
        chip.enqueue_rx(partner_data_frame(DataMsg::Request, &[prdo.encode()]));
        let _ = port.step(&cap).unwrap();
        if port.state() != SourceState::TransitionSupply {
            return TestResult::Fail("PPS Accept should advance to TransitionSupply");
        }
        let outcome = port.step(&cap).unwrap();
        let contract = match outcome {
            SourceStepOutcome::Ready { contract } => contract,
            _ => return TestResult::Fail("expected Ready outcome"),
        };
        if contract.voltage_mv != 9000
            || contract.op_current_ma != 2000
            || contract.object_position != 2
        {
            return TestResult::Fail("PPS contract drift");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_pps_source_accepts_programmable_request
    );

    fn smoke_pps_source_rejects_out_of_range_voltage() -> TestResult {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Rd,
            cc2: CcState::Open,
        }));
        let policy = SourcePolicy::from_pdos(alloc::vec![
            SourcePdo::Fixed {
                voltage_mv: 5000,
                max_current_ma: 3000,
            },
            SourcePdo::Augmented {
                max_voltage_mv: 11000,
                min_voltage_mv: 3300,
                max_current_ma: 3000,
            },
        ]);
        let port = SourcePort::new(chip.clone(), policy);
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        for _ in 0..3 {
            let _ = port.step(&cap).unwrap();
        }
        let prdo = ProgrammableRdo {
            object_position: 2,
            voltage_mv: 20000, // out of APDO range
            op_current_ma: 1000,
            usb_comms: true,
            no_usb_suspend: true,
            cap_mismatch: false,
        };
        chip.enqueue_rx(partner_data_frame(DataMsg::Request, &[prdo.encode()]));
        let _ = port.step(&cap).unwrap();
        let sent = chip.sent();
        let (h, _) = decode_message(sent.last().unwrap()).unwrap();
        if CtrlMsg::from_u8(h.msg_type) != Some(CtrlMsg::Reject) {
            return TestResult::Fail("out-of-range PPS request should be Rejected");
        }
        if port.state() != SourceState::NegotiateCapability {
            return TestResult::Fail("Reject should stay in NegotiateCapability");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/tcpm",
        smoke_pps_source_rejects_out_of_range_voltage
    );

    // ── BIST ──────────────────────────────────────────────────────

    fn smoke_bist_inbound_carrier_mode2_parks() -> TestResult {
        let (chip, port) = fresh_source_port();
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        let _ = drive_to_ready(&port, &chip, &cap, 8);
        let bdo = BistDataObject {
            mode: BistMode::CarrierMode2,
        };
        chip.enqueue_rx(partner_data_frame(DataMsg::Bist, &[bdo.encode()]));
        let outcome = port.step(&cap).unwrap();
        match outcome {
            SourceStepOutcome::BistEntered => {
                if port.state() != SourceState::BistCarrierMode {
                    return TestResult::Fail("BIST entry should park in BistCarrierMode");
                }
                let next = port.step(&cap).unwrap();
                match next {
                    SourceStepOutcome::Idle(SourceState::BistCarrierMode) => TestResult::Pass,
                    _ => TestResult::Fail("BIST should idle after entry"),
                }
            }
            _ => TestResult::Fail("expected BistEntered outcome"),
        }
    }
    kernel_test_in!("drivers/usbpd/tcpm", smoke_bist_inbound_carrier_mode2_parks);

    fn smoke_bist_tcpmport_relays_outcome() -> TestResult {
        let chip = Arc::new(FakeChip::new(CcStatus {
            cc1: CcState::Rd,
            cc2: CcState::Open,
        }));
        let port = TcpmPort::new(
            chip.clone(),
            SinkPolicy::default(),
            SourcePolicy::default(),
            alloc::string::String::from("bist-port"),
        );
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        let _ = port.step(&cap).unwrap(); // Unattached → AttachedSrc
        for _ in 0..6 {
            if port.source().state() == SourceState::NegotiateCapability {
                chip.enqueue_rx(request_frame(1, 1500, 0));
            }
            let _ = port.step(&cap).unwrap();
        }
        if port.source().state() != SourceState::Ready {
            return TestResult::Fail("source did not reach Ready");
        }
        let bdo = BistDataObject {
            mode: BistMode::CarrierMode2,
        };
        chip.enqueue_rx(partner_data_frame(DataMsg::Bist, &[bdo.encode()]));
        let outcome = port.step(&cap).unwrap();
        match outcome {
            PortStepOutcome::BistEntered => {
                if port.state() != PortState::Bist {
                    return TestResult::Fail("TcpmPort should hop to Bist on BistEntered");
                }
                TestResult::Pass
            }
            _ => TestResult::Fail("expected PortStepOutcome::BistEntered"),
        }
    }
    kernel_test_in!("drivers/usbpd/tcpm", smoke_bist_tcpmport_relays_outcome);
}
