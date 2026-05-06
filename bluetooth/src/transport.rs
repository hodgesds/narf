//! HCI transport abstraction.
//!
//! Vol 4 Part B (USB Transport Layer) and Vol 4 Part A (UART
//! Transport Layer) define the same packet shape over different
//! physical pipes. We hide that behind a trait so the controller
//! state machine doesn't care which is in use.
//!
//! USB transport mapping per Vol 4 Part B §2.1:
//!
//! | Endpoint               | Direction | Packet type        |
//! | ---------------------- | --------- | ------------------ |
//! | EP0 (Control)          | OUT       | HCI Command        |
//! | EP1 (Interrupt IN)     | IN        | HCI Event          |
//! | EP2 (Bulk IN/OUT)      | IN/OUT    | ACL Data           |
//! | EP1 (Isoch IN/OUT)     | IN/OUT    | Synchronous Data   |
//!
//! USB-IF class identifier per "USB Class Definitions for Wireless
//! Controllers" v1.0: class 0xE0, subclass 0x01, protocol 0x01.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;

use narf_lib::sync::IrqSafeSpinLock;

use crate::hci::{Command, Event, PacketType};

/// USB Wireless-Controller class triple per §USB-IF Class Defs.
pub const USB_CLASS_WIRELESS: u8 = 0xE0;
pub const USB_SUBCLASS_RF: u8 = 0x01;
pub const USB_PROTOCOL_BLUETOOTH: u8 = 0x01;

/// Errors a transport may surface to the controller.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// Underlying I/O timed out (e.g. EP1 IN bulk did not complete).
    Timeout,
    /// USB stall on the control / event endpoint — controller is
    /// gone.
    EndpointStalled,
    /// Transport is registered but its host (USB hub) was unplugged.
    Detached,
    /// Generic catch-all for non-fatal transport errors that should
    /// trigger a retry.
    Transient,
}

/// HCI transport interface. One instance per Bluetooth controller.
pub trait HciTransport: Send + Sync + Debug {
    /// Submit a Command packet (the 0x01 indicator is added by the
    /// transport when needed; on USB the indicator is implicit in the
    /// EP0 control transfer's `bRequest`).
    fn send_command(&self, cmd: &Command) -> Result<(), TransportError>;

    /// Pull the next Event packet. Should park (yield / await IRQ)
    /// when no event is pending. Returns `None` on a clean shutdown.
    fn recv_event(&self) -> Result<Option<Event>, TransportError>;

    /// Submit an ACL data packet.
    fn send_acl(&self, data: &[u8]) -> Result<(), TransportError>;

    /// Pull pending ACL data. Returns `None` when no data is ready.
    fn recv_acl(&self) -> Result<Option<Vec<u8>>, TransportError>;

    /// Stable transport name for diagnostics ("usb", "uart-115200",
    /// "vhci-test").
    fn name(&self) -> &'static str;
}

// ── Registry ────────────────────────────────────────────────────────

static TRANSPORTS: IrqSafeSpinLock<Vec<Arc<dyn HciTransport>>> = IrqSafeSpinLock::new(Vec::new());

/// Register an HCI transport. Multiple controllers (USB Bluetooth
/// dongle + onboard) coexist as separate registry entries.
pub fn register(t: Arc<dyn HciTransport>) {
    TRANSPORTS.lock().push(t);
}

/// Snapshot every registered transport.
pub fn transports() -> Vec<Arc<dyn HciTransport>> {
    TRANSPORTS.lock().clone()
}

/// Number of registered transports.
pub fn transport_count() -> usize {
    TRANSPORTS.lock().len()
}

/// Test helper: drain the registry.
#[doc(hidden)]
pub fn __test_reset() {
    TRANSPORTS.lock().clear();
}

// ── Test transport ──────────────────────────────────────────────────

/// In-memory loopback transport. The bring-up smoke uses this to
/// exercise the controller state machine without a real USB stack.
/// Pre-canned events get queued; the controller pulls them via
/// `recv_event` after sending each command.
#[derive(Debug)]
pub struct LoopbackTransport {
    inbox: IrqSafeSpinLock<Vec<Event>>,
    sent: IrqSafeSpinLock<Vec<Command>>,
    name: &'static str,
}

impl LoopbackTransport {
    pub fn new(name: &'static str) -> Self {
        Self {
            inbox: IrqSafeSpinLock::new(Vec::new()),
            sent: IrqSafeSpinLock::new(Vec::new()),
            name,
        }
    }

    /// Push an event onto the inbox so a future `recv_event` returns it.
    pub fn enqueue_event(&self, e: Event) {
        self.inbox.lock().push(e);
    }

    /// Snapshot every command the controller has sent.
    pub fn sent_commands(&self) -> Vec<Command> {
        self.sent.lock().clone()
    }
}

impl HciTransport for LoopbackTransport {
    fn send_command(&self, cmd: &Command) -> Result<(), TransportError> {
        self.sent.lock().push(cmd.clone());
        Ok(())
    }

    fn recv_event(&self) -> Result<Option<Event>, TransportError> {
        let mut inbox = self.inbox.lock();
        if inbox.is_empty() {
            return Ok(None);
        }
        Ok(Some(inbox.remove(0)))
    }

    fn send_acl(&self, _data: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }

    fn recv_acl(&self) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(None)
    }

    fn name(&self) -> &'static str {
        self.name
    }
}
