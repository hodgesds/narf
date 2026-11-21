//! Command-ring abort after a command timeout.
//!
//! The controller executes the Command Ring strictly in order. A
//! command it cannot finish — an Address Device whose SET_ADDRESS a
//! hung device never acknowledges, a Stop Endpoint that never
//! completes — keeps the ring Running on that TRB, and every command
//! queued behind it waits with it. Retiring the timed-out receipt
//! alone (what this driver did before) leaves the controller stuck:
//! every later Enable Slot, Address Device, Configure Endpoint or
//! Stop Endpoint on the controller then times out too.
//!
//! Linux (`drivers/usb/host/xhci-ring.c`):
//! - `xhci_handle_command_timeout`: a timed-out Stop Endpoint is
//!   fatal (`xhci_halt` + `xhci_hc_died`). Otherwise, with the ring
//!   Running (CRCR.CRR), mark the command aborted and call
//!   `xhci_abort_cmd_ring`; with the ring already stopped, call
//!   `xhci_handle_stopped_cmd_ring` directly.
//! - `xhci_abort_cmd_ring`: write CRCR with Command Abort (CA), wait
//!   up to 5 s for CRR to clear (xHCI 1.0 §4.6.1.2) — a ring that does
//!   not stop is a dead controller — then up to 2 s for the Command
//!   Ring Stopped completion.
//! - `xhci_handle_stopped_cmd_ring`: turn every aborted command still
//!   on the ring into a No Op (`trb_to_noop`), then ring the command
//!   doorbell to restart the ring if commands remain.
//!
//! The aborted command itself completes with Command Aborted (25);
//! the receipt its waiter abandoned swallows that completion, and the
//! No Op completions of the rewritten TRBs, so each ring entry is
//! released only once the controller has dequeued it.
//!
//! Discipline mirrors `control_cancel`: the coordinator sees the
//! controller only through [`Bus`], so the fixtures can model a ring
//! that never completes a command.

use core::future::Future;

/// Completion code: Command Ring Stopped (xHCI 1.2 §6.4.5 Table 6-90).
pub(super) const CC_COMMAND_RING_STOPPED: u8 = 24;
/// Completion code: Command Aborted — what the executing command reports
/// after CRCR.CA; its abandoned receipt swallows it like any other
/// completion, so only the fixtures name it.
#[allow(dead_code)]
pub(super) const CC_COMMAND_ABORTED: u8 = 25;
/// TRB type of the Stop Endpoint command (§6.4.3.8).
pub(super) const TRB_STOP_ENDPOINT: u32 = 15;
/// TRB type of the No Op command (§6.4.3.1).
pub(super) const TRB_NO_OP_COMMAND: u32 = 23;
/// CRCR.CRR must clear within this bound after CRCR.CA (Linux
/// `xhci_abort_cmd_ring`: 5 s, xHCI 1.0 §4.6.1.2).
pub(super) const ABORT_HANDSHAKE_MS: u64 = 5_000;
/// The Command Ring Stopped completion must follow within this bound
/// once CRR cleared (Linux: 2 s, "on some host hw the CMD_RING_RUNNING
/// bit is correctly cleared but the completion event in never sent").
pub(super) const STOP_EVENT_MS: u64 = 2_000;

/// How a command timeout was handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    /// The ring was stopped (aborted, or found stopped), the abandoned
    /// commands on it became No Ops and the ring was restarted.
    Restarted,
    /// The controller must be reset: a Stop Endpoint timed out, or the
    /// abort did not stop the ring. Recovery has been requested.
    Fatal,
}

/// What the coordinator can observe and do on one controller.
pub(super) trait Bus: Sync {
    /// CRCR.CRR: the Command Ring is Running.
    fn ring_running(&self) -> bool;
    /// Write CRCR with Command Abort set.
    fn write_abort(&self);
    /// Move pending events through the demux; true once a Command Ring
    /// Stopped completion has been seen (consuming it).
    fn take_ring_stopped(&self) -> bool;
    /// Rewrite every abandoned command the controller has not completed
    /// as a No Op Command TRB, keeping its cycle bit. Returns how many.
    fn noop_abandoned(&self) -> usize;
    /// Ring the command doorbell if any command remains on the ring.
    fn restart(&self);
    /// Request a full controller recovery (Linux `xhci_hc_died`).
    fn fatal(&self);
    /// Monotonic milliseconds.
    fn now_ms(&self) -> u64;
    /// One cooperative wait step between register polls.
    fn pause(&self) -> impl Future<Output = ()> + Send;
}

/// Handle the timeout of a command whose TRB type is `timed_out_type`.
/// The waiter has already abandoned its receipt.
pub(super) async fn handle_timeout<B: Bus>(bus: &B, timed_out_type: u32) -> Outcome {
    if timed_out_type == TRB_STOP_ENDPOINT {
        // "xHCI host not responding to stop endpoint command".
        bus.fatal();
        return Outcome::Fatal;
    }
    if bus.ring_running() {
        // A stale stop notification must not satisfy this abort.
        let _ = bus.take_ring_stopped();
        bus.write_abort();
        let start = bus.now_ms();
        while bus.ring_running() {
            if bus.now_ms().saturating_sub(start) >= ABORT_HANDSHAKE_MS {
                // "Abort failed to stop command ring".
                bus.fatal();
                return Outcome::Fatal;
            }
            bus.pause().await;
        }
        let start = bus.now_ms();
        while !bus.take_ring_stopped() {
            if bus.now_ms().saturating_sub(start) >= STOP_EVENT_MS {
                // "No stop event for abort, ring start fail?"
                bus.fatal();
                return Outcome::Fatal;
            }
            bus.pause().await;
        }
    }
    // Stopped: either by the abort above or already ("Command timeout
    // on stopped ring"). The controller now owns no TRB between its
    // dequeue pointer and the enqueue pointer.
    bus.noop_abandoned();
    bus.restart();
    Outcome::Restarted
}

#[cfg(feature = "kernel-test")]
#[path = "cmd_abort_tests.rs"]
mod tests;
