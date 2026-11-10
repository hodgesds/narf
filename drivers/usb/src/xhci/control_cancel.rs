//! Cancellation of a timed-out control TD on EP0 (DCI 1).
//!
//! A control transfer whose stage wait expires still owns EP0: its
//! Setup/Data/Status TRBs stay published and the `ControlState` claim
//! stays busy, so every later request on the device fails `NotReady`.
//! Linux gives the TD back with `usb_kill_urb` → `xhci_urb_dequeue`
//! (Stop Endpoint), then `xhci_handle_cmd_stop_ep` →
//! `xhci_invalidate_cancelled_tds` moves the dequeue pointer past it
//! (Set TR Dequeue Pointer). A Stop Endpoint that fails with Context
//! State Error because the endpoint halted in the meantime is routed
//! to Reset Endpoint (`xhci_handle_halted_endpoint`) instead.
//! xHCI 1.2 §4.6.8–§4.6.10.
//!
//! Discipline mirrors `bulk_stop`: claim first, publish second; once
//! claimed, any error leaves the claim closed (EP0 terminally busy)
//! rather than reopening a ring the controller may still walk.
use super::bulk_stop::{Context, Error};
use core::future::Future;

const STATE_RUNNING: u8 = 1;
const STATE_HALTED: u8 = 2;
const STATE_STOPPED: u8 = 3;
const CC_SUCCESS: u8 = 1;
const CC_CONTEXT_STATE_ERROR: u8 = 19;
const CMD_RESET_ENDPOINT: u32 = 14;
const CMD_STOP_ENDPOINT: u32 = 15;
const CMD_SET_TR_DEQUEUE: u32 = 16;

/// The successor cursor the control ring restarts from: `target` is
/// the Set TR Dequeue Pointer operand (ring address of `enqueue`,
/// bit 0 = Dequeue Cycle State).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Plan {
    pub slot: u8,
    pub generation: u64,
    pub target: u64,
    pub enqueue: usize,
    pub cycle: u32,
}
impl Plan {
    fn command(&self, kind: u32, dequeue: u64) -> [u32; 4] {
        [
            dequeue as u32,
            (dequeue >> 32) as u32,
            0,
            kind << 10 | u32::from(self.slot) << 24 | 1 << 16,
        ]
    }
}

pub(super) trait Bus: Sync {
    type Error: From<Error>;
    /// Claims slot configuration and quarantines EP0's Transfer Events
    /// before any command; fails when no control TD is retained.
    fn claim(&self) -> Result<Plan, Self::Error>;
    /// Must match the exact command TRB and slot. Returns the command's
    /// completion code; transport failures (timeout, ring full) are `Err`.
    fn command(&self, words: [u32; 4]) -> impl Future<Output = Result<u8, Self::Error>> + Send;
    /// EP0 output-context state and TR Dequeue Pointer.
    fn context(&self, plan: &Plan) -> Result<Context, Self::Error>;
    /// Purges EP0's queued events, releases the control claim, and
    /// publishes the plan's cursor as the ring's software position.
    fn commit(&self, plan: Plan) -> Result<(), Self::Error>;
}

pub(super) async fn run<B: Bus>(bus: &B) -> Result<(), B::Error> {
    let plan = bus.claim()?;
    let mut state = bus.context(&plan)?.state;
    if state == STATE_RUNNING {
        // Context State Error is not a failure here: the endpoint left
        // Running by itself between the readback and the command (it
        // halted on a late error, or stopped). The readback decides.
        let code = bus.command(plan.command(CMD_STOP_ENDPOINT, 0)).await?;
        if code != CC_SUCCESS && code != CC_CONTEXT_STATE_ERROR {
            return Err(Error::State.into());
        }
        state = bus.context(&plan)?.state;
    }
    if state == STATE_HALTED {
        if bus.command(plan.command(CMD_RESET_ENDPOINT, 0)).await? != CC_SUCCESS {
            return Err(Error::State.into());
        }
        state = bus.context(&plan)?.state;
    }
    if state != STATE_STOPPED {
        return Err(Error::State.into());
    }
    if bus
        .command(plan.command(CMD_SET_TR_DEQUEUE, plan.target))
        .await?
        != CC_SUCCESS
    {
        return Err(Error::State.into());
    }
    let context = bus.context(&plan)?;
    if context.state != STATE_STOPPED {
        return Err(Error::State.into());
    }
    if context.dequeue != plan.target {
        return Err(Error::Pointer.into());
    }
    bus.commit(plan)
}

#[cfg(feature = "kernel-test")]
#[path = "control_cancel_tests.rs"]
mod tests;
