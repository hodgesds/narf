//! USB4 entry (EnterUSB) — port driver.
//!
//! After the TCPM reaches a live contract, USB4 entry carries a port
//! from "explicit contract live" to "USB4 alt mode entered" (issue
//! #1194). USB4 has no SVID, so unlike DP Alt Mode there is no
//! Enter Mode exchange: the DFP discovers the partner's identity,
//! confirms the USB4 capability bit in UFP VDO1, and transmits the
//! Enter_USB data message (USB PD 3.1 §6.4.9) carrying the entry
//! parameters. EnterUSB has no response VDM — transmission is the
//! completion signal on the initiator side.
//!
//! Spec sources (public, non-GPL):
//! - **USB Power Delivery 3.1 v1.8** (USB-IF), §6.4.9 (Enter_USB),
//!   §6.4.4.3 (Discover Identity).
//!   <https://www.usb.org/document-library/usb-power-delivery>
//!
//! The pure EUDO codec lives in `narf_usbpd::message` and the
//! unscheduled `Usb4EntryDriver` state machine in `narf_usbpd::vdm`.
//! This module wires the driver to a `TcpmPort`, mirroring
//! `altmode_dp::DpAltModePort`:
//!
//! 1. Wait for the underlying port to reach a live contract (call
//!    site checks `contract_live`).
//! 2. Initiator side (source-attached, i.e. DFP in this stack's
//!    model): Discover Identity → on a USB4-capable ACK, transmit
//!    the Enter_USB message → `Active`.
//! 3. Responder side (sink-attached, i.e. UFP): answer Discover
//!    Identity with a USB4-capable ACK, and record any inbound
//!    Enter_USB message in `entered_eudo` — that receipt is the
//!    port's "USB4 alt mode entered" signal.
//! 4. Frames of any other class found in RX while polling are
//!    dropped, following `DpAltModePort::poll_vdm`'s precedent: the
//!    engines do not consume post-contract traffic in Ready, and
//!    the entry poll only cares about its own exchange.
//!
//! Production task registration is deliberately NOT wired here
//! (contrast `altmode_dp`, registered per port in `lib.rs`):
//! the entry parameters a real host transmits must come from its
//! own capabilities and the SOP' cable discovery (#1215), not from
//! fixture values. The API + fixture coverage land first; the
//! one-line registration follows once real host caps exist.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, Ordering};

use narf_capabilities::{Cap, CapError, Grant, NoopOp};
use narf_lib::sync::IrqSafeSpinLock;
use narf_usbpd::message::{
    decode_message, encode_message, DataMsg, DataRole, EnterUsbDataObject, Header, PowerRole,
    SpecRev,
};
use narf_usbpd::tcpc::TcpcError;
use narf_usbpd::vdm::{
    build_usb4_identity_ack, CommandType, Usb4EntryDriver, Usb4EntryOutcome, Usb4EntryState,
    VdmCommand, VdmHeader,
};
use narf_usbpd::UsbPd;

use crate::tcpm::{PortState, TcpmPort};

/// Error from the port-side USB4 entry driver.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Usb4EntryError {
    AuthorityRevoked,
    Tcpc(TcpcError),
    /// Underlying PD message decode failed.
    Protocol,
}

impl From<CapError> for Usb4EntryError {
    fn from(_: CapError) -> Self {
        Usb4EntryError::AuthorityRevoked
    }
}

impl From<TcpcError> for Usb4EntryError {
    fn from(e: TcpcError) -> Self {
        Usb4EntryError::Tcpc(e)
    }
}

/// Outcome of one [`Usb4EntryPort::step`] call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Usb4EntryStep {
    /// Nothing to do — wait for the port to reach a contract.
    NotReady,
    /// State machine advanced (frame sent / response consumed). Call
    /// step() again soon.
    Advanced(Usb4EntryState),
    /// Initiator side: the Enter_USB message was transmitted.
    Active,
    /// Responder side: an Enter_USB message was received and
    /// recorded; carries the received entry parameters.
    Entered(EnterUsbDataObject),
    /// Entry failed (NAK, partner not USB4-capable, or malformed).
    Failed,
}

/// One USB4 entry driver bound to a TCPM port.
#[derive(Debug)]
pub struct Usb4EntryPort {
    port: Arc<TcpmPort>,
    driver: IrqSafeSpinLock<Usb4EntryDriver>,
    next_msg_id: AtomicU8,
    /// Inbound Enter_USB parameters, once a valid one is observed.
    entered: IrqSafeSpinLock<Option<EnterUsbDataObject>>,
    /// Vendor id the responder side claims in its Discover Identity
    /// ACK. Fixture value in tests; the device's real VID on
    /// hardware.
    identity_vid: u16,
}

impl Usb4EntryPort {
    pub fn new(port: Arc<TcpmPort>, entry_params: EnterUsbDataObject, identity_vid: u16) -> Self {
        Self {
            port,
            driver: IrqSafeSpinLock::new(Usb4EntryDriver::new(entry_params)),
            next_msg_id: AtomicU8::new(0),
            entered: IrqSafeSpinLock::new(None),
            identity_vid,
        }
    }

    /// Initiator-side driver state. The responder side never leaves
    /// `Idle` — its signal is [`usb4_entered`], not this state.
    pub fn state(&self) -> Usb4EntryState {
        self.driver.lock().state
    }

    /// True once a valid inbound Enter_USB message was recorded.
    pub fn usb4_entered(&self) -> bool {
        self.entered.lock().is_some()
    }

    /// The received entry parameters, if any.
    pub fn entered_eudo(&self) -> Option<EnterUsbDataObject> {
        *self.entered.lock()
    }

    pub fn port_label(&self) -> &str {
        &self.port.label
    }

    fn next_msg_id(&self) -> u8 {
        let v = self.next_msg_id.fetch_add(1, Ordering::AcqRel);
        v & 0x7
    }

    /// Send a VDM (frame payload is one or more 32-bit Data Objects,
    /// the first being the VDM header). The initiator is the DFP
    /// source, mirroring `DpAltModePort::transmit_vdm`.
    fn transmit_vdm(&self, vdos: &[u32]) -> Result<(), Usb4EntryError> {
        if vdos.is_empty() {
            return Err(Usb4EntryError::Protocol);
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

    /// Send the Enter_USB data message (single EUDO object).
    fn transmit_enter_usb(&self, eudo: EnterUsbDataObject) -> Result<(), Usb4EntryError> {
        let h = Header::data(
            DataMsg::EnterUsb,
            DataRole::Dfp,
            PowerRole::Source,
            SpecRev::R3_0,
            self.next_msg_id(),
            1,
        );
        let frame = encode_message(h, &[eudo.encode()]);
        self.port.tcpc().transmit(&frame)?;
        Ok(())
    }

    /// Send a Discover Identity ACK as the responder (UFP sink).
    fn transmit_identity_ack(&self) -> Result<(), Usb4EntryError> {
        let vdos = build_usb4_identity_ack(self.identity_vid);
        let h = Header::data(
            DataMsg::VendorDefined,
            DataRole::Ufp,
            PowerRole::Sink,
            SpecRev::R3_0,
            self.next_msg_id(),
            vdos.len() as u8,
        );
        let frame = encode_message(h, &vdos);
        self.port.tcpc().transmit(&frame)?;
        Ok(())
    }

    /// One entry step. Caller drives this from a poll loop.
    pub fn step(&self, cap: &Cap<UsbPd, Grant>) -> Result<Usb4EntryStep, Usb4EntryError> {
        cap.invoke(NoopOp)?;
        if !self.port.contract_live() {
            return Ok(Usb4EntryStep::NotReady);
        }
        if matches!(self.driver.lock().state, Usb4EntryState::Active) {
            return Ok(Usb4EntryStep::Active);
        }
        if matches!(self.driver.lock().state, Usb4EntryState::Failed) {
            return Ok(Usb4EntryStep::Failed);
        }

        // Pump one RX frame if available.
        let buf = match self.port.tcpc().receive() {
            Ok(b) => b,
            Err(TcpcError::NoMessage) => {
                // Nothing to consume: kick off discovery on the
                // initiator side, idle on the responder side.
                if matches!(self.driver.lock().state, Usb4EntryState::Idle)
                    && self.port.state() == PortState::AttachedSrc
                {
                    let mut sm = self.driver.lock();
                    let outcome = sm.start();
                    drop(sm);
                    if let Usb4EntryOutcome::TransmitVdm(vdos) = outcome {
                        self.transmit_vdm(&vdos)?;
                    }
                    return Ok(Usb4EntryStep::Advanced(self.driver.lock().state));
                }
                return Ok(Usb4EntryStep::Advanced(self.driver.lock().state));
            }
            Err(e) => return Err(Usb4EntryError::Tcpc(e)),
        };
        let (h, objs) = decode_message(&buf).ok_or(Usb4EntryError::Protocol)?;

        // Inbound Enter_USB: record it on either side. A valid EUDO
        // is the port's "USB4 alt mode entered" signal; a malformed
        // one is dropped, not fatal.
        if DataMsg::from_u8(h.msg_type) == Some(DataMsg::EnterUsb) && !objs.is_empty() {
            if let Some(eudo) = EnterUsbDataObject::decode(objs[0]) {
                *self.entered.lock() = Some(eudo);
                return Ok(Usb4EntryStep::Entered(eudo));
            }
            return Ok(Usb4EntryStep::Advanced(self.driver.lock().state));
        }

        if DataMsg::from_u8(h.msg_type) != Some(DataMsg::VendorDefined) || objs.is_empty() {
            // Non-VDM frame while polling — not necessarily fatal
            // (could be a normal PD heartbeat); silently drop and
            // try again, following DpAltModePort::poll_vdm.
            return Ok(Usb4EntryStep::Advanced(self.driver.lock().state));
        }

        // VDM frame: responder answers Discover Identity REQs,
        // initiator feeds everything else to the driver.
        let vh = VdmHeader::decode(objs[0]);
        if matches!(self.driver.lock().state, Usb4EntryState::Idle)
            && self.port.state() == PortState::AttachedSnk
            && vh.command_type == CommandType::Req
            && VdmCommand::from_u8(vh.command) == Some(VdmCommand::DiscoverIdentity)
        {
            self.transmit_identity_ack()?;
            return Ok(Usb4EntryStep::Advanced(Usb4EntryState::Idle));
        }
        if !matches!(
            self.driver.lock().state,
            Usb4EntryState::DiscoveringIdentity
        ) {
            return Ok(Usb4EntryStep::Advanced(self.driver.lock().state));
        }
        let mut sm = self.driver.lock();
        let outcome = sm.feed_response(&objs);
        let state = sm.state;
        drop(sm);
        match outcome {
            Usb4EntryOutcome::TransmitVdm(vdos) => {
                self.transmit_vdm(&vdos)?;
                Ok(Usb4EntryStep::Advanced(state))
            }
            Usb4EntryOutcome::TransmitEnterUsb(eudo) => {
                self.transmit_enter_usb(eudo)?;
                self.driver.lock().mark_entered();
                Ok(Usb4EntryStep::Active)
            }
            Usb4EntryOutcome::Failed => Ok(Usb4EntryStep::Failed),
        }
    }
}
