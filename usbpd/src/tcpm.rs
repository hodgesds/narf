//! Type-C Port Manager — sink-role state machine.
//!
//! USB-PD 3.1 §8.3.3.3 prescribes the sink Policy Engine state
//! sequence. We implement the linear path needed to land a fixed
//! 5V contract from a connected source, plus the PR/DR/VConn swap
//! machines (the sink halves of §8.3.3.4 / §8.3.3.5 / §8.3.3.6):
//! the sink answers partner-initiated swaps in Ready and can
//! initiate swaps itself; a completed PR_Swap flips the port to
//! source role and the contract is renegotiated from scratch.
//! PPS remains a later extension.
//!   <https://www.usb.org/document-library/usb-power-delivery>
//!   <https://www.usb.org/document-library/usb-type-c-cable-and-connector-specification-revision-22>
//!   <https://www.usb.org/document-library/usb-type-c-port-controller-interface-specification-revision-20>
//!
//! Phase order:
//!
//!   Unattached → AttachWait → Attached → SinkStartup → SinkDiscovery →
//!   SinkWaitCaps → SinkEvaluateCaps → SinkSelectCapability →
//!   SinkTransitionSink → SinkReady.
//!
//! `step()` is driven by the caller (a periodic task or a TCPC
//! interrupt handler). Each step consumes one TCPC event (CC change
//! or RX message) and advances the state at most one phase.
//!
//! In `Ready` the engine also drains one inbound message per step:
//! PR_Swap / DR_Swap / VConn_Swap are answered per the swap policy
//! (default: reject all), and SoftReset is answered with Accept
//! followed by a fresh negotiation from Startup. Unknown control
//! messages are consumed and ignored; unexpected data messages are
//! a protocol error, mirroring the source engine's Ready handling.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};

use narf_capabilities::{Cap, CapError, Grant, NoopOp};
use narf_lib::sync::IrqSafeSpinLock;

use crate::message::{
    decode_message, encode_message, CtrlMsg, DataMsg, DataRole, FixedRdo, Header, PowerRole,
    SourcePdo, SpecRev,
};
use crate::tcpc::{PortRole, Tcpc, TcpcError};
use crate::UsbPd;

/// Sink Policy Engine state (§8.3.3.3).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SinkState {
    Unattached = 0,
    AttachWait = 1,
    Attached = 2,
    Startup = 3,
    Discovery = 4,
    WaitCaps = 5,
    EvaluateCaps = 6,
    SelectCapability = 7,
    TransitionSink = 8,
    Ready = 9,
    HardReset = 10,
    /// PR_Swap sent by us; waiting for Accept/Reject/Wait.
    PrSwapSend = 11,
    /// PR_Swap reply pending (initiator side).
    PrSwapWaitReply = 12,
    /// PR_Swap accepted (either side); waiting for the partner's
    /// PS_RDY signalling its Vbus is off, before we turn ours on.
    PrSwapWaitOff = 13,
    /// DR_Swap sent by us; waiting for Accept/Reject/Wait.
    DrSwapSend = 14,
    /// DR_Swap reply pending (initiator side).
    DrSwapWaitReply = 15,
    /// DR_Swap accepted; data role flips here.
    DrSwapChange = 16,
    /// VConn_Swap sent by us; waiting for Accept/Reject/Wait.
    VconnSwapSend = 17,
    /// VConn_Swap reply pending (initiator side).
    VconnSwapWaitReply = 18,
    /// VConn_Swap accepted and we are not supplying: we become the
    /// supplier and emit PS_RDY.
    VconnSwapStart = 19,
    /// VConn_Swap accepted and we are supplying: we wait for the
    /// partner's PS_RDY, then release VConn.
    VconnSwapTurnOff = 20,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SinkError {
    AuthorityRevoked,
    Tcpc(TcpcError),
    /// Source advertised 0 PDOs.
    NoPdos,
    /// Source rejected our Request and we ran out of fallbacks.
    Rejected,
    /// State machine got an unexpected message.
    Protocol,
}

impl From<CapError> for SinkError {
    fn from(_: CapError) -> Self {
        SinkError::AuthorityRevoked
    }
}

impl From<TcpcError> for SinkError {
    fn from(e: TcpcError) -> Self {
        SinkError::Tcpc(e)
    }
}

/// One outcome of `step()`. The driving task should keep stepping
/// while it's not `Idle` or `Ready`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    /// The state machine moved forward; call `step()` again right
    /// away if convenient.
    Advanced(SinkState),
    /// No work to do — wait for a TCPC interrupt.
    Idle(SinkState),
    /// Negotiated a contract; `Ready` state — sink can accept Vbus.
    Ready { contract: Contract },
    /// PR_Swap completed — this port is now a *source*. The driving
    /// task re-enters the port as a source; the contract is
    /// renegotiated from scratch (the sink engine parks in
    /// `Unattached`, mirroring the source engine parking in
    /// `Startup` on its own RoleSwappedToSink).
    RoleSwappedToSource,
    /// DR_Swap completed — data role flipped.
    DataRoleSwapped { now_dfp: bool },
    /// VConn_Swap completed — our VConn-supplier flag flipped.
    VconnSwapped { now_supplying: bool },
}

/// Active power contract negotiated with the source.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Contract {
    /// The PDO position we requested (1-based per §6.4.2.1).
    pub object_position: u8,
    /// Negotiated voltage in mV. For Fixed PDOs this is the PDO's
    /// voltage; for PPS it's the requested voltage.
    pub voltage_mv: u32,
    /// Negotiated operating current in mA.
    pub op_current_ma: u32,
}

/// Swap policy consulted when the partner requests a role swap
/// while this port is a sink. Mirrors the three accept flags on the
/// drivers-side `SinkPolicy`; the default rejects every swap, which
/// matches "most non-DRP sinks reject swap".
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SinkSwapPolicy {
    /// `true` to Accept inbound PR_Swap requests.
    pub accept_pr_swap: bool,
    /// `true` to Accept inbound DR_Swap requests.
    pub accept_dr_swap: bool,
    /// `true` to Accept inbound VConn_Swap requests.
    pub accept_vconn_swap: bool,
}

/// Sink-role policy engine running on top of a TCPC.
#[derive(Debug)]
pub struct SinkPort {
    tcpc: Arc<dyn Tcpc>,
    state: AtomicU8,
    /// Most recently received Source_Capabilities, copied for the
    /// EvaluateCaps step.
    last_source_caps: IrqSafeSpinLock<Vec<SourcePdo>>,
    /// Outgoing message ID, modulo 8 per §6.7.1.1.
    next_msg_id: AtomicU8,
    /// Latest contract; only meaningful in `SinkState::Ready`.
    contract: IrqSafeSpinLock<Option<Contract>>,
    /// Swap policy (configuration, not session state: `reset()` on
    /// detach intentionally keeps it).
    swap_policy: IrqSafeSpinLock<SinkSwapPolicy>,
    /// Current data role. Sink-role typically starts UFP; flips on
    /// every successful DR_Swap. `true` = DFP, `false` = UFP.
    is_dfp: AtomicU8,
    /// Are we currently supplying VConn on the active CC pin? Sinks
    /// default to not supplying; flips on every successful
    /// VConn_Swap.
    is_vconn_supplier: AtomicU8,
}

impl SinkPort {
    pub fn new(tcpc: Arc<dyn Tcpc>) -> Self {
        Self {
            tcpc,
            state: AtomicU8::new(SinkState::Unattached as u8),
            last_source_caps: IrqSafeSpinLock::new(Vec::new()),
            next_msg_id: AtomicU8::new(0),
            contract: IrqSafeSpinLock::new(None),
            swap_policy: IrqSafeSpinLock::new(SinkSwapPolicy::default()),
            is_dfp: AtomicU8::new(0),
            is_vconn_supplier: AtomicU8::new(0),
        }
    }

    pub fn state(&self) -> SinkState {
        // Safety: we only ever store SinkState discriminants.
        let v = self.state.load(Ordering::Acquire);
        // SAFETY: source and destination have identical size and a compatible layout.
        unsafe { core::mem::transmute(v) }
    }

    pub fn contract(&self) -> Option<Contract> {
        *self.contract.lock()
    }

    /// Install the swap policy consulted for inbound swap requests.
    /// The drivers-side `TcpmPort` maps its `SinkPolicy` accept flags
    /// through here; the default (all false) rejects every swap.
    pub fn set_swap_policy(&self, policy: SinkSwapPolicy) {
        *self.swap_policy.lock() = policy;
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

    /// Set the data-role flag directly. Used by the port driver to
    /// carry the role across a PR_Swap: data role is a port-level
    /// property, not per-engine state, so the engine taking over
    /// after a swap must inherit the role the previous engine held.
    pub fn set_dfp(&self, dfp: bool) {
        self.is_dfp
            .store(if dfp { 1 } else { 0 }, Ordering::Release);
    }

    /// Set the VConn-supplier flag directly. Same carry-across-a-
    /// swap rationale as `set_dfp`: VConn supply is independent of
    /// power role, so it must survive a PR_Swap unchanged.
    pub fn set_vconn_supplier(&self, supplying: bool) {
        self.is_vconn_supplier
            .store(if supplying { 1 } else { 0 }, Ordering::Release);
    }

    /// Return the port to its freshly-constructed state:
    /// `Unattached`, received capabilities and any contract dropped,
    /// message counter reset, data role back to UFP and VConn supply
    /// released. A driving task that observes a detach (CC lost)
    /// calls this so a later re-attach runs a fresh negotiation
    /// instead of reporting the previous partner's contract as live
    /// (#1193). The swap policy is configuration and survives.
    pub fn reset(&self) {
        *self.last_source_caps.lock() = Vec::new();
        *self.contract.lock() = None;
        self.next_msg_id.store(0, Ordering::Release);
        self.is_dfp.store(0, Ordering::Release);
        self.is_vconn_supplier.store(0, Ordering::Release);
        self.set_state(SinkState::Unattached);
    }

    /// Run one step of the sink state machine. Caller should arm
    /// this from a timer or TCPC interrupt — the state machine
    /// pulls one event per call.
    pub fn step(&self, cap: &Cap<UsbPd, Grant>) -> Result<StepOutcome, SinkError> {
        cap.invoke(NoopOp)?;
        let cur = self.state();
        match cur {
            SinkState::Unattached => self.step_unattached(),
            SinkState::AttachWait => self.step_attach_wait(),
            SinkState::Attached => self.step_attached(),
            SinkState::Startup => {
                self.set_state(SinkState::Discovery);
                Ok(StepOutcome::Advanced(SinkState::Discovery))
            }
            SinkState::Discovery => {
                // Wait for Source_Capabilities — the source wakes the
                // bus periodically per §6.6.1 with caps. Stay idle
                // until RX has something.
                self.set_state(SinkState::WaitCaps);
                Ok(StepOutcome::Advanced(SinkState::WaitCaps))
            }
            SinkState::WaitCaps => self.step_wait_caps(),
            SinkState::EvaluateCaps => self.step_evaluate_caps(),
            SinkState::SelectCapability => self.step_select_capability(),
            SinkState::TransitionSink => self.step_transition_sink(),
            SinkState::Ready => self.step_ready_or_handle_inbound(),
            SinkState::PrSwapSend => self.step_pr_swap_send(),
            SinkState::PrSwapWaitReply => self.step_pr_swap_wait_reply(),
            SinkState::PrSwapWaitOff => self.step_pr_swap_wait_off(),
            SinkState::DrSwapSend => self.step_dr_swap_send(),
            SinkState::DrSwapWaitReply => self.step_dr_swap_wait_reply(),
            SinkState::DrSwapChange => self.step_dr_swap_change(),
            SinkState::VconnSwapSend => self.step_vconn_swap_send(),
            SinkState::VconnSwapWaitReply => self.step_vconn_swap_wait_reply(),
            SinkState::VconnSwapStart => self.step_vconn_swap_start(),
            SinkState::VconnSwapTurnOff => self.step_vconn_swap_turn_off(),
            SinkState::HardReset => {
                self.tcpc.hard_reset().ok();
                self.set_state(SinkState::Unattached);
                Ok(StepOutcome::Advanced(SinkState::Unattached))
            }
        }
    }

    fn set_state(&self, s: SinkState) {
        self.state.store(s as u8, Ordering::Release);
    }

    fn next_msg_id(&self) -> u8 {
        let v = self.next_msg_id.fetch_add(1, Ordering::AcqRel);
        v & 0x7
    }

    fn data_role(&self) -> DataRole {
        if self.is_dfp() {
            DataRole::Dfp
        } else {
            DataRole::Ufp
        }
    }

    fn send_control(&self, msg: CtrlMsg) -> Result<(), SinkError> {
        let h = Header::control(
            msg,
            self.data_role(),
            PowerRole::Sink,
            SpecRev::R3_0,
            self.next_msg_id(),
        );
        let frame = encode_message(h, &[]);
        self.tcpc.transmit(&frame)?;
        Ok(())
    }

    /// Externally request a PR_Swap. Only legal from `Ready`.
    /// Returns false if the sink is in another state.
    pub fn initiate_pr_swap(&self) -> bool {
        if self.state() != SinkState::Ready {
            return false;
        }
        self.set_state(SinkState::PrSwapSend);
        true
    }

    /// Externally request a DR_Swap. Only legal from `Ready`.
    pub fn initiate_dr_swap(&self) -> bool {
        if self.state() != SinkState::Ready {
            return false;
        }
        self.set_state(SinkState::DrSwapSend);
        true
    }

    /// Externally request a VConn_Swap. Only legal from `Ready`.
    pub fn initiate_vconn_swap(&self) -> bool {
        if self.state() != SinkState::Ready {
            return false;
        }
        self.set_state(SinkState::VconnSwapSend);
        true
    }

    fn step_unattached(&self) -> Result<StepOutcome, SinkError> {
        // Set port role to Sink so CC1/CC2 pull down; wait for CC
        // change. §4.5.2.1.
        self.tcpc.set_role(PortRole::Sink)?;
        let cc = self.tcpc.cc_status()?;
        if cc.attached() {
            self.set_state(SinkState::AttachWait);
            Ok(StepOutcome::Advanced(SinkState::AttachWait))
        } else {
            Ok(StepOutcome::Idle(SinkState::Unattached))
        }
    }

    fn step_attach_wait(&self) -> Result<StepOutcome, SinkError> {
        // §4.5.2.2.3: tCCDebounce ≈ 100..200 ms; we let the caller
        // pace the polling. Confirm CC stayed attached.
        let cc = self.tcpc.cc_status()?;
        if !cc.attached() {
            self.set_state(SinkState::Unattached);
            return Ok(StepOutcome::Advanced(SinkState::Unattached));
        }
        self.set_state(SinkState::Attached);
        Ok(StepOutcome::Advanced(SinkState::Attached))
    }

    fn step_attached(&self) -> Result<StepOutcome, SinkError> {
        // §8.3.3.3.1 PE_SNK_Startup. Reset message-id counter, clear
        // any stale state, transition to Startup.
        self.next_msg_id.store(0, Ordering::Release);
        self.last_source_caps.lock().clear();
        *self.contract.lock() = None;
        self.set_state(SinkState::Startup);
        Ok(StepOutcome::Advanced(SinkState::Startup))
    }

    fn step_wait_caps(&self) -> Result<StepOutcome, SinkError> {
        // Pull next message; if it's Source_Capabilities, advance.
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => return Ok(StepOutcome::Idle(SinkState::WaitCaps)),
            Err(e) => return Err(SinkError::Tcpc(e)),
        };
        let (h, objs) = decode_message(&buf).ok_or(SinkError::Protocol)?;
        if h.num_data_objects > 0
            && DataMsg::from_u8(h.msg_type) == Some(DataMsg::SourceCapabilities)
        {
            let pdos: Vec<SourcePdo> = objs.iter().map(|o| SourcePdo::decode(*o)).collect();
            if pdos.is_empty() {
                return Err(SinkError::NoPdos);
            }
            *self.last_source_caps.lock() = pdos;
            self.set_state(SinkState::EvaluateCaps);
            Ok(StepOutcome::Advanced(SinkState::EvaluateCaps))
        } else {
            // Anything else — protocol error; soft-reset by going
            // back to Unattached.
            self.set_state(SinkState::Unattached);
            Ok(StepOutcome::Advanced(SinkState::Unattached))
        }
    }

    fn step_evaluate_caps(&self) -> Result<StepOutcome, SinkError> {
        // §8.3.3.3.4: pick a PDO. Simple policy: pick the first
        // Fixed PDO we see (every source advertises Fixed 5 V at
        // position 1 per §6.4.1.3.1). Future policies (max-power,
        // PPS preference) plug in here.
        let caps = self.last_source_caps.lock().clone();
        let mut pos: Option<u8> = None;
        let mut chosen_voltage = 0u32;
        let mut chosen_current = 0u32;
        for (i, pdo) in caps.iter().enumerate() {
            if let SourcePdo::Fixed {
                voltage_mv,
                max_current_ma,
                ..
            } = pdo
            {
                pos = Some((i + 1) as u8);
                chosen_voltage = *voltage_mv;
                chosen_current = *max_current_ma;
                break;
            }
        }
        let pos = pos.ok_or(SinkError::NoPdos)?;
        *self.contract.lock() = Some(Contract {
            object_position: pos,
            voltage_mv: chosen_voltage,
            op_current_ma: chosen_current,
        });
        self.set_state(SinkState::SelectCapability);
        Ok(StepOutcome::Advanced(SinkState::SelectCapability))
    }

    fn step_select_capability(&self) -> Result<StepOutcome, SinkError> {
        // §8.3.3.3.5: send Request, then wait for Accept.
        let pending = self.contract.lock().ok_or(SinkError::Protocol)?;
        let rdo = FixedRdo {
            object_position: pending.object_position,
            op_current_ma: pending.op_current_ma,
            max_op_current_ma: pending.op_current_ma,
            give_back: false,
            usb_comms: false,
            no_usb_suspend: false,
            cap_mismatch: false,
            epr_mode_capable: false,
        };
        let h = Header::data(
            DataMsg::Request,
            DataRole::Ufp,
            PowerRole::Sink,
            SpecRev::R3_0,
            self.next_msg_id(),
            1,
        );
        let frame = encode_message(h, &[rdo.encode()]);
        self.tcpc.transmit(&frame)?;
        self.set_state(SinkState::TransitionSink);
        Ok(StepOutcome::Advanced(SinkState::TransitionSink))
    }

    fn step_transition_sink(&self) -> Result<StepOutcome, SinkError> {
        // Wait for Accept, then PS_RDY.
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => return Ok(StepOutcome::Idle(SinkState::TransitionSink)),
            Err(e) => return Err(SinkError::Tcpc(e)),
        };
        let (h, _) = decode_message(&buf).ok_or(SinkError::Protocol)?;
        if h.num_data_objects != 0 {
            // Spurious data message during transition — protocol error.
            return Err(SinkError::Protocol);
        }
        match CtrlMsg::from_u8(h.msg_type) {
            Some(CtrlMsg::Accept) => {
                // Stay in TransitionSink waiting for PS_RDY.
                Ok(StepOutcome::Idle(SinkState::TransitionSink))
            }
            Some(CtrlMsg::PsRdy) => {
                self.set_state(SinkState::Ready);
                let contract = self.contract.lock().ok_or(SinkError::Protocol)?;
                Ok(StepOutcome::Ready { contract })
            }
            Some(CtrlMsg::Reject) | Some(CtrlMsg::Wait) => {
                self.set_state(SinkState::HardReset);
                Err(SinkError::Rejected)
            }
            _ => Err(SinkError::Protocol),
        }
    }

    // ── Ready-state inbound handling ───────────────────────────────

    /// In `Ready` the partner may send PR_Swap, DR_Swap, VConn_Swap
    /// or SoftReset. Drain at most one inbound message per step; if
    /// there is nothing we idle. Unknown control messages are
    /// consumed and ignored; unexpected data messages are a protocol
    /// error, mirroring the source engine's Ready handling.
    fn step_ready_or_handle_inbound(&self) -> Result<StepOutcome, SinkError> {
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => return Ok(StepOutcome::Idle(SinkState::Ready)),
            Err(e) => return Err(SinkError::Tcpc(e)),
        };
        let (h, _) = decode_message(&buf).ok_or(SinkError::Protocol)?;
        if h.num_data_objects > 0 {
            // No data message is legal in Ready on the sink side.
            self.set_state(SinkState::HardReset);
            return Err(SinkError::Protocol);
        }
        match CtrlMsg::from_u8(h.msg_type) {
            Some(CtrlMsg::PrSwap) => self.handle_inbound_pr_swap(),
            Some(CtrlMsg::DrSwap) => self.handle_inbound_dr_swap(),
            Some(CtrlMsg::VconnSwap) => self.handle_inbound_vconn_swap(),
            Some(CtrlMsg::SoftReset) => {
                // §6.3.13: respond with Accept, reset the message-id
                // counter, and restart from Startup so the contract
                // is renegotiated fresh.
                self.send_control(CtrlMsg::Accept)?;
                self.next_msg_id.store(0, Ordering::Release);
                self.set_state(SinkState::Startup);
                Ok(StepOutcome::Advanced(SinkState::Startup))
            }
            _ => Ok(StepOutcome::Idle(SinkState::Ready)),
        }
    }

    // ── PR_Swap ────────────────────────────────────────────────────

    fn step_pr_swap_send(&self) -> Result<StepOutcome, SinkError> {
        self.send_control(CtrlMsg::PrSwap)?;
        self.set_state(SinkState::PrSwapWaitReply);
        Ok(StepOutcome::Advanced(SinkState::PrSwapWaitReply))
    }

    fn step_pr_swap_wait_reply(&self) -> Result<StepOutcome, SinkError> {
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => return Ok(StepOutcome::Idle(SinkState::PrSwapWaitReply)),
            Err(e) => return Err(SinkError::Tcpc(e)),
        };
        let (h, _) = decode_message(&buf).ok_or(SinkError::Protocol)?;
        match CtrlMsg::from_u8(h.msg_type) {
            Some(CtrlMsg::Accept) => {
                self.set_state(SinkState::PrSwapWaitOff);
                Ok(StepOutcome::Advanced(SinkState::PrSwapWaitOff))
            }
            Some(CtrlMsg::Reject) | Some(CtrlMsg::Wait) => {
                // Partner declined; stay a sink.
                self.set_state(SinkState::Ready);
                Ok(StepOutcome::Advanced(SinkState::Ready))
            }
            _ => Err(SinkError::Protocol),
        }
    }

    /// Both sides of a PR_Swap join here once the swap is accepted:
    /// the old source turns its Vbus off and sends PS_RDY; we wait
    /// for that PS_RDY (two sources must never drive Vbus at once),
    /// then turn our rail on, send PS_RDY, and flip to source role.
    /// The TCPC trait exposes no Vbus enable — like the source
    /// engine, we emit PS_RDY and let the chip-level driver own the
    /// rail. The contract is dropped: the new source renegotiates
    /// from scratch.
    fn step_pr_swap_wait_off(&self) -> Result<StepOutcome, SinkError> {
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => return Ok(StepOutcome::Idle(SinkState::PrSwapWaitOff)),
            Err(e) => return Err(SinkError::Tcpc(e)),
        };
        let (h, _) = decode_message(&buf).ok_or(SinkError::Protocol)?;
        if CtrlMsg::from_u8(h.msg_type) != Some(CtrlMsg::PsRdy) {
            return Err(SinkError::Protocol);
        }
        self.send_control(CtrlMsg::PsRdy)?;
        self.tcpc.set_role(PortRole::Source)?;
        *self.contract.lock() = None;
        self.set_state(SinkState::Unattached);
        Ok(StepOutcome::RoleSwappedToSource)
    }

    fn handle_inbound_pr_swap(&self) -> Result<StepOutcome, SinkError> {
        // The responder evaluates policy and Accepts / Rejects. On
        // Accept the responder waits for the partner's PS_RDY — same
        // path as initiated PR_Swap from PrSwapWaitOff onward.
        let accept = self.swap_policy.lock().accept_pr_swap;
        if accept {
            self.send_control(CtrlMsg::Accept)?;
            self.set_state(SinkState::PrSwapWaitOff);
            Ok(StepOutcome::Advanced(SinkState::PrSwapWaitOff))
        } else {
            self.send_control(CtrlMsg::Reject)?;
            self.set_state(SinkState::Ready);
            Ok(StepOutcome::Advanced(SinkState::Ready))
        }
    }

    // ── DR_Swap ────────────────────────────────────────────────────

    fn step_dr_swap_send(&self) -> Result<StepOutcome, SinkError> {
        self.send_control(CtrlMsg::DrSwap)?;
        self.set_state(SinkState::DrSwapWaitReply);
        Ok(StepOutcome::Advanced(SinkState::DrSwapWaitReply))
    }

    fn step_dr_swap_wait_reply(&self) -> Result<StepOutcome, SinkError> {
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => return Ok(StepOutcome::Idle(SinkState::DrSwapWaitReply)),
            Err(e) => return Err(SinkError::Tcpc(e)),
        };
        let (h, _) = decode_message(&buf).ok_or(SinkError::Protocol)?;
        match CtrlMsg::from_u8(h.msg_type) {
            Some(CtrlMsg::Accept) => {
                self.set_state(SinkState::DrSwapChange);
                Ok(StepOutcome::Advanced(SinkState::DrSwapChange))
            }
            Some(CtrlMsg::Reject) | Some(CtrlMsg::Wait) => {
                self.set_state(SinkState::Ready);
                Ok(StepOutcome::Advanced(SinkState::Ready))
            }
            _ => Err(SinkError::Protocol),
        }
    }

    fn step_dr_swap_change(&self) -> Result<StepOutcome, SinkError> {
        // Flip the data role and return to Ready.
        let now_dfp = !self.is_dfp();
        self.is_dfp
            .store(if now_dfp { 1 } else { 0 }, Ordering::Release);
        self.set_state(SinkState::Ready);
        Ok(StepOutcome::DataRoleSwapped { now_dfp })
    }

    fn handle_inbound_dr_swap(&self) -> Result<StepOutcome, SinkError> {
        let accept = self.swap_policy.lock().accept_dr_swap;
        if accept {
            self.send_control(CtrlMsg::Accept)?;
            self.set_state(SinkState::DrSwapChange);
            Ok(StepOutcome::Advanced(SinkState::DrSwapChange))
        } else {
            self.send_control(CtrlMsg::Reject)?;
            self.set_state(SinkState::Ready);
            Ok(StepOutcome::Advanced(SinkState::Ready))
        }
    }

    // ── VConn_Swap ─────────────────────────────────────────────────

    fn step_vconn_swap_send(&self) -> Result<StepOutcome, SinkError> {
        self.send_control(CtrlMsg::VconnSwap)?;
        self.set_state(SinkState::VconnSwapWaitReply);
        Ok(StepOutcome::Advanced(SinkState::VconnSwapWaitReply))
    }

    fn step_vconn_swap_wait_reply(&self) -> Result<StepOutcome, SinkError> {
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => {
                return Ok(StepOutcome::Idle(SinkState::VconnSwapWaitReply))
            }
            Err(e) => return Err(SinkError::Tcpc(e)),
        };
        let (h, _) = decode_message(&buf).ok_or(SinkError::Protocol)?;
        match CtrlMsg::from_u8(h.msg_type) {
            Some(CtrlMsg::Accept) => {
                // VConn-source goes to Turn_off; VConn-sink goes to
                // Start. We pick by our current state, mirroring the
                // source engine.
                let next = if self.is_vconn_supplier() {
                    SinkState::VconnSwapTurnOff
                } else {
                    SinkState::VconnSwapStart
                };
                self.set_state(next);
                Ok(StepOutcome::Advanced(next))
            }
            Some(CtrlMsg::Reject) | Some(CtrlMsg::Wait) => {
                self.set_state(SinkState::Ready);
                Ok(StepOutcome::Advanced(SinkState::Ready))
            }
            _ => Err(SinkError::Protocol),
        }
    }

    fn step_vconn_swap_start(&self) -> Result<StepOutcome, SinkError> {
        // We are now the VConn supplier; emit PS_RDY so the partner
        // can finish turning theirs off.
        self.send_control(CtrlMsg::PsRdy)?;
        self.is_vconn_supplier.store(1, Ordering::Release);
        self.set_state(SinkState::Ready);
        Ok(StepOutcome::VconnSwapped {
            now_supplying: true,
        })
    }

    fn step_vconn_swap_turn_off(&self) -> Result<StepOutcome, SinkError> {
        // Wait for partner's PS_RDY, then release VConn.
        let buf = match self.tcpc.receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => return Ok(StepOutcome::Idle(SinkState::VconnSwapTurnOff)),
            Err(e) => return Err(SinkError::Tcpc(e)),
        };
        let (h, _) = decode_message(&buf).ok_or(SinkError::Protocol)?;
        if CtrlMsg::from_u8(h.msg_type) != Some(CtrlMsg::PsRdy) {
            return Err(SinkError::Protocol);
        }
        self.is_vconn_supplier.store(0, Ordering::Release);
        self.set_state(SinkState::Ready);
        Ok(StepOutcome::VconnSwapped {
            now_supplying: false,
        })
    }

    fn handle_inbound_vconn_swap(&self) -> Result<StepOutcome, SinkError> {
        let accept = self.swap_policy.lock().accept_vconn_swap;
        if accept {
            self.send_control(CtrlMsg::Accept)?;
            let next = if self.is_vconn_supplier() {
                SinkState::VconnSwapTurnOff
            } else {
                SinkState::VconnSwapStart
            };
            self.set_state(next);
            Ok(StepOutcome::Advanced(next))
        } else {
            self.send_control(CtrlMsg::Reject)?;
            self.set_state(SinkState::Ready);
            Ok(StepOutcome::Advanced(SinkState::Ready))
        }
    }
}

// ── Registry ────────────────────────────────────────────────────────

static PORTS: IrqSafeSpinLock<Vec<Arc<SinkPort>>> = IrqSafeSpinLock::new(Vec::new());

/// Register a sink-role port with the global registry.
pub fn register(port: Arc<SinkPort>) {
    PORTS.lock().push(port);
}

/// Snapshot every registered port.
pub fn ports() -> Vec<Arc<SinkPort>> {
    PORTS.lock().clone()
}

/// Test helper.
#[doc(hidden)]
pub fn __test_reset() {
    PORTS.lock().clear();
}
