//! HCI Command Queue — outstanding command tracking.
//!
//! ## Background
//!
//! Bluetooth Core Spec 5.3 Vol 4 Part E §4.4 defines the HCI flow-
//! control model for commands:
//!
//! - The controller grants the host a credit count in the
//!   `Num_HCI_Command_Packets` field of every `HCI_Command_Complete`
//!   or `HCI_Command_Status` event.
//! - The host MUST NOT send more commands than it currently holds
//!   credits for.
//! - At reset the host should assume one initial credit.
//!
//! ## This implementation
//!
//! [`CmdQueue`] is a credit-managed FIFO that:
//!
//! 1. Holds pending commands when the credit count is zero.
//! 2. Tracks the opcode of each in-flight command so the caller can
//!    match incoming `Command_Complete` / `Command_Status` events
//!    against the correct callback.
//! 3. Updates the credit count when `notify_cmd_complete` or
//!    `notify_cmd_status` is called by the event dispatcher.
//!
//! The queue runs in a single-threaded poll / async context — the
//! `IrqSafeSpinLock` wrapper lets the transport IRQ handler replenish
//! credits without a separate lock hierarchy.
//!
//! ## Linux reference
//!
//! `net/bluetooth/hci_core.c` — `hci_cmd_work`, `hci_cmd_complete_evt`,
//! `hci_cmd_status_evt`.  The credit model and pending-queue drain logic
//! mirror Linux's `hdev->cmd_cnt` + `hdev->cmd_q`.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::hci::Command;
use crate::transport::{HciTransport, TransportError};

/// Entry in the command queue.
#[derive(Clone, Debug)]
pub struct QueuedCommand {
    /// The HCI command to send.
    pub cmd: Command,
}

/// Credit-managed HCI command queue.
///
/// Create one per controller. The queue serialises command issue and
/// provides the controller's `cmd_complete` / `cmd_status` event
/// handlers with the opcode that triggered each event.
#[derive(Debug)]
pub struct CmdQueue {
    inner: IrqSafeSpinLock<CmdQueueInner>,
}

#[derive(Debug)]
struct CmdQueueInner {
    /// Commands waiting to be sent (not yet issued to the transport).
    pending: VecDeque<QueuedCommand>,
    /// Opcodes of commands sent to the controller but whose
    /// Command_Complete / Command_Status has not yet arrived.
    in_flight: Vec<u16>,
    /// Controller's advertised command-credit count.  Starts at 1
    /// per §4.4.1; updated by every Command_Complete /
    /// Command_Status `Num_HCI_Command_Packets` field.
    credits: u8,
}

impl CmdQueue {
    /// Create a new queue with one initial credit (§4.4.1).
    pub fn new() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(CmdQueueInner {
                pending: VecDeque::new(),
                in_flight: Vec::new(),
                credits: 1,
            }),
        }
    }

    /// Number of pending commands not yet sent to the transport.
    pub fn pending_len(&self) -> usize {
        self.inner.lock().pending.len()
    }

    /// Opcodes of in-flight commands (sent, awaiting Command_Complete).
    pub fn in_flight_opcodes(&self) -> Vec<u16> {
        self.inner.lock().in_flight.clone()
    }

    /// Current credit count as reported by the controller.
    pub fn credits(&self) -> u8 {
        self.inner.lock().credits
    }

    /// Enqueue a command. If a credit is available it is sent
    /// immediately to `transport`; otherwise it sits in the pending
    /// queue until `drain` is called after a credit replenishment.
    ///
    /// Returns `Err` only on a transport failure for the immediate
    /// send path; queued entries never fail at enqueue time.
    pub fn enqueue(
        &self,
        cmd: Command,
        transport: &dyn HciTransport,
    ) -> Result<(), TransportError> {
        let mut inner = self.inner.lock();
        if inner.credits > 0 {
            inner.credits -= 1;
            let opcode = cmd.opcode;
            transport.send_command(&cmd)?;
            inner.in_flight.push(opcode);
        } else {
            inner.pending.push_back(QueuedCommand { cmd });
        }
        Ok(())
    }

    /// Called when a `Command_Complete` or `Command_Status` event
    /// arrives. Updates credits and removes the matching opcode from
    /// the in-flight list.
    ///
    /// Returns the opcode that completed (useful for routing the
    /// return parameters to the right handler).
    pub fn notify_complete(&self, opcode: u16, new_credits: u8) -> Option<u16> {
        let mut inner = self.inner.lock();
        inner.credits = new_credits;
        // Remove the first matching in-flight entry.
        if let Some(pos) = inner.in_flight.iter().position(|&op| op == opcode) {
            inner.in_flight.remove(pos);
            Some(opcode)
        } else {
            // Command_Complete for an opcode we didn't issue (e.g. NOP
            // or Flush from the controller) — still update credits.
            None
        }
    }

    /// Drain the pending queue into `transport` up to the current
    /// credit limit. Call after processing a `Command_Complete` or
    /// `Command_Status` event.
    ///
    /// Returns the number of commands flushed, or the first
    /// transport error encountered.
    pub fn drain(&self, transport: &dyn HciTransport) -> Result<usize, TransportError> {
        let mut count = 0usize;
        loop {
            let mut inner = self.inner.lock();
            if inner.credits == 0 || inner.pending.is_empty() {
                break;
            }
            let entry = inner.pending.pop_front().expect("checked non-empty");
            inner.credits -= 1;
            let opcode = entry.cmd.opcode;
            // Drop the lock before issuing the transport call so the
            // IRQ path can update credits concurrently.
            drop(inner);
            transport.send_command(&entry.cmd)?;
            self.inner.lock().in_flight.push(opcode);
            count += 1;
        }
        Ok(count)
    }
}

impl Default for CmdQueue {
    fn default() -> Self {
        Self::new()
    }
}
