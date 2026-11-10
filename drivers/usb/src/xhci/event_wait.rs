//! Shared bounded command/transfer waiter and queue pressure policy.
//! Unrelated hardware traffic must never hide a queued completion behind an
//! unbounded drain, or prevent a deadline check and cooperative yield.

use alloc::collections::VecDeque;

pub(super) type Event = [u32; 4];
pub(super) const QUEUE_DEPTH: usize = 64;
pub(super) const DRAIN_BUDGET: usize = 32;

/// Deadline class of one wait.
///
/// Linux allows commands and control-transfer stages 5000 ms
/// (`XHCI_CMD_DEFAULT_TIMEOUT`, `USB_CTRL_GET_TIMEOUT`), and USB 2.0
/// §9.2.6.1 lets a device take that long. This driver cannot yet afford
/// it: `Xhci::await_event` waits by re-polling on every executor round
/// instead of sleeping, so a silent device keeps the USB supervisor
/// runnable for the whole deadline. With 5000 ms, one unresponsive
/// high-speed device on a physical host held it for tens of seconds and
/// the boot never reached the display manager. Every class therefore
/// keeps the 250 ms bound until that wait can block; the classes stay
/// distinct so the longer bounds can return without touching callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Wait {
    Command,
    ControlStage,
    Transfer,
}
impl Wait {
    pub const fn timeout_ms(self) -> u64 {
        match self {
            Self::Command | Self::ControlStage | Self::Transfer => 250,
        }
    }
}

/// Returns true if an unrelated oldest event had to be discarded.
pub(super) fn enqueue(queue: &mut VecDeque<Event>, event: Event) -> bool {
    let overflow = queue.len() >= QUEUE_DEPTH;
    if overflow {
        queue.pop_front();
    }
    queue.push_back(event);
    overflow
}

pub(super) fn take_matching(
    queue: &mut VecDeque<Event>,
    predicate: &mut dyn FnMut(&Event) -> bool,
) -> Option<Event> {
    let index = queue.iter().position(predicate)?;
    queue.remove(index)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PollError<E> {
    TimedOut,
    Source(E),
}

/// One executor poll's bounded work. Inspect queues before each additional
/// event, including the last event of a full batch. None requires the async
/// caller to yield before trying another batch. The callbacks never await.
pub(super) fn poll_batch<E>(
    mut take: impl FnMut() -> Result<Option<Event>, E>,
    mut demux: impl FnMut() -> bool,
    mut expired: impl FnMut() -> bool,
) -> Result<Option<Event>, PollError<E>> {
    for _ in 0..DRAIN_BUDGET {
        if let Some(event) = take().map_err(PollError::Source)? {
            return Ok(Some(event));
        }
        if expired() {
            return Err(PollError::TimedOut);
        }
        if !demux() {
            return if expired() {
                Err(PollError::TimedOut)
            } else {
                Ok(None)
            };
        }
    }
    if let Some(event) = take().map_err(PollError::Source)? {
        Ok(Some(event))
    } else if expired() {
        Err(PollError::TimedOut)
    } else {
        Ok(None)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "event_wait_tests.rs"]
mod tests;

pub(super) fn command_pointer_matches(event: &Event, pointer: u64) -> bool {
    let origin = u64::from(event[0]) | u64::from(event[1]) << 32;
    event[3] & (0x3f << 10) == 33 << 10 && origin & !15 == pointer
}
