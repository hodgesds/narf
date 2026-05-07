//! Type-C Port Manager — sink-role state machine.
//!
//! USB-PD 3.1 §8.3.3.3 prescribes the sink Policy Engine state
//! sequence. We implement the linear path needed to land a fixed
//! 5V contract from a connected source — extensions (PR/DR swap,
//! PPS) come later.
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
}

impl SinkPort {
    pub fn new(tcpc: Arc<dyn Tcpc>) -> Self {
        Self {
            tcpc,
            state: AtomicU8::new(SinkState::Unattached as u8),
            last_source_caps: IrqSafeSpinLock::new(Vec::new()),
            next_msg_id: AtomicU8::new(0),
            contract: IrqSafeSpinLock::new(None),
        }
    }

    pub fn state(&self) -> SinkState {
        // Safety: we only ever store SinkState discriminants.
        let v = self.state.load(Ordering::Acquire);
        unsafe { core::mem::transmute(v) }
    }

    pub fn contract(&self) -> Option<Contract> {
        *self.contract.lock()
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
            SinkState::Ready => Ok(StepOutcome::Idle(SinkState::Ready)),
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
