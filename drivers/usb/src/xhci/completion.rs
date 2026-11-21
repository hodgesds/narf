//! Bounded retained terminal events for hardware-owned operations.
//! Shared event queues may overflow; an exact active receipt must not.
use super::event_wait::Event;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Conflict;

#[derive(Debug)]
pub(super) struct Latch {
    event: Option<Event>,
    consumed: bool,
    conflict: bool,
}
impl Latch {
    pub const fn new() -> Self {
        Self {
            event: None,
            consumed: false,
            conflict: false,
        }
    }
    /// Caller checked originating TRB/slot/endpoint before invoking this.
    /// Exact duplicates are idempotent; differing terminal results poison it.
    pub fn record(&mut self, event: Event) {
        if let Some(first) = self.event {
            if first[..3] != event[..3] || first[3] & !1 != event[3] & !1 {
                self.conflict = true;
            }
        } else {
            self.event = Some(event);
        }
    }
    pub fn take_matching(
        &mut self,
        predicate: &mut dyn FnMut(&Event) -> bool,
    ) -> Result<Option<Event>, Conflict> {
        let Some(event) = self.event else {
            return Ok(None);
        };
        if !predicate(&event) {
            return Ok(None);
        }
        if self.conflict {
            return Err(Conflict);
        }
        if self.consumed {
            return Ok(None);
        }
        self.consumed = true;
        Ok(Some(event))
    }
    pub fn conflicted(&self) -> bool {
        self.conflict
    }
    /// The latched event, without consuming it (diagnostics only).
    pub fn peek(&self) -> Option<Event> {
        self.event
    }
    pub fn consumed(&self) -> bool {
        self.consumed && !self.conflict
    }
}

#[derive(Debug)]
struct Command {
    pointer: u64,
    slot: u8,
    completion: Latch,
    /// The waiter timed out and gave the receipt up (#884). The entry
    /// stays reserved until the controller completes the command —
    /// normally, with Command Aborted, or as the No Op it was turned
    /// into — so the ring entry is never reused while the controller
    /// may still fetch it, and that completion is swallowed here.
    abandoned: bool,
    /// Publication order: the controller executes commands in order.
    seq: u64,
}
/// At most one retained receipt per physical command-ring entry.
///
/// A waiter that times out abandons its receipt (`retire_pointer`)
/// instead of dropping it: the command TRB is still on the ring, and
/// the controller executes the ring in order, so the entry cannot be
/// reused until the controller's completion for it arrives. That
/// completion — success, failure, Command Aborted after a ring abort,
/// or No Op success after `cmd_abort` rewrote the TRB — is swallowed
/// by `record` and releases the entry (Linux frees a command only on
/// its completion; `xhci_handle_stopped_cmd_ring` turns aborted ones
/// into No Ops so they complete).
///
/// A Command Ring Stopped completion (code 24) names the ring's
/// dequeue pointer, i.e. the next command to execute, not a completed
/// one: it never completes a receipt and is reported through
/// [`Self::take_ring_stopped`] instead (Linux `handle_cmd_completion`
/// completes `cmd_ring_stop_completion` and returns).
///
/// Commands execute in ring order, so a completion for one command
/// proves every command published before it was executed: an abandoned
/// one whose own completion was lost (event ring overflow) is released
/// then too, instead of holding its entry forever.
pub(super) struct Commands {
    pending: Vec<Option<Command>>,
    ring_stopped: bool,
    next_seq: u64,
}
impl Commands {
    pub fn new(entries: usize) -> Self {
        Self {
            pending: core::iter::repeat_with(|| None).take(entries).collect(),
            ring_stopped: false,
            next_seq: 0,
        }
    }
    /// Whether any command is still on the ring (waited for or
    /// abandoned).
    pub fn active(&self) -> bool {
        self.pending.iter().any(Option::is_some)
    }
    /// Drop every retained receipt. Controller recovery calls this
    /// after the hardware reset: the command ring's cursors restart
    /// from zero, so a stale receipt could otherwise alias a recycled
    /// ring entry's pointer and let a dead operation's waiter consume
    /// a new command's completion. Waiters on cleared receipts time
    /// out, which is the honest outcome for a reset controller.
    pub fn clear(&mut self) {
        for value in self.pending.iter_mut() {
            *value = None;
        }
        self.ring_stopped = false;
    }
    pub fn reserve(&mut self, entry: usize, pointer: u64, slot: u8) -> Result<(), Conflict> {
        let value = self.pending.get_mut(entry).ok_or(Conflict)?;
        if value.is_some() {
            return Err(Conflict);
        }
        *value = Some(Command {
            pointer,
            slot,
            completion: Latch::new(),
            abandoned: false,
            seq: self.next_seq,
        });
        self.next_seq += 1;
        Ok(())
    }
    /// Release every abandoned command published before `seq`: the
    /// controller has executed it, whatever became of its completion.
    fn release_abandoned_before(&mut self, seq: u64) {
        for value in self.pending.iter_mut() {
            if value
                .as_ref()
                .is_some_and(|command| command.abandoned && command.seq < seq)
            {
                *value = None;
            }
        }
    }
    fn seq_at(&self, event: &Event) -> Option<u64> {
        self.pending
            .iter()
            .flatten()
            .find(|command| super::event_wait::command_pointer_matches(event, command.pointer))
            .map(|command| command.seq)
    }
    /// Abandon the receipt for a command whose waiter timed out
    /// (#884). Returns whether a waited-for receipt was abandoned;
    /// false when the pointer was already consumed, abandoned or
    /// never reserved. Pointers are unique per ring entry, so at most
    /// one receipt matches.
    pub fn retire_pointer(&mut self, pointer: u64) -> bool {
        for command in self.pending.iter_mut().flatten() {
            if command.pointer == pointer && !command.abandoned {
                command.abandoned = true;
                return true;
            }
        }
        false
    }
    pub fn record(&mut self, event: Event) -> bool {
        if event[3] & (0x3f << 10) == 33 << 10
            && (event[2] >> 24) as u8 == super::cmd_abort::CC_COMMAND_RING_STOPPED
        {
            // The ring stopped on the command it names (or on an empty
            // slot): everything published before it was executed.
            let stopped_at = self.seq_at(&event).unwrap_or(u64::MAX);
            self.release_abandoned_before(stopped_at);
            self.ring_stopped = true;
            return true;
        }
        if let Some(seq) = self.seq_at(&event) {
            self.release_abandoned_before(seq);
        }
        for value in self.pending.iter_mut() {
            let Some(command) = value else {
                continue;
            };
            if !super::event_wait::command_pointer_matches(&event, command.pointer) {
                continue;
            }
            if command.abandoned {
                // Its waiter is gone: the completion only releases the
                // entry. A No Op or aborted command reports slot 0, so
                // the pointer alone identifies it.
                *value = None;
                return true;
            }
            if command.slot == 0 || event[3] >> 24 == u32::from(command.slot) {
                command.completion.record(event);
                return true;
            }
        }
        false
    }
    pub fn take_matching(
        &mut self,
        predicate: &mut dyn FnMut(&Event) -> bool,
    ) -> Result<Option<Event>, Conflict> {
        for value in &mut self.pending {
            if let Some(command) = value {
                if command.abandoned {
                    continue;
                }
                if let Some(event) = command.completion.take_matching(predicate)? {
                    *value = None;
                    return Ok(Some(event));
                }
            }
        }
        Ok(None)
    }
    /// Whether a Command Ring Stopped completion arrived since the last
    /// call (consumes it).
    pub fn take_ring_stopped(&mut self) -> bool {
        core::mem::take(&mut self.ring_stopped)
    }
    /// Ring entries whose waiter gave up and whose command the
    /// controller has not completed yet.
    pub fn abandoned_entries(&self) -> Vec<usize> {
        self.pending
            .iter()
            .enumerate()
            .filter(|(_, value)| value.as_ref().is_some_and(|command| command.abandoned))
            .map(|(entry, _)| entry)
            .collect()
    }
}

pub(super) fn transfer_matches(event: &Event, slot: u8, dci: u8, pointer: u64) -> bool {
    let origin = u64::from(event[0]) | u64::from(event[1]) << 32;
    event[3] & (0x3f << 10) == 32 << 10
        && event[3] & (1 << 2) == 0
        && event[3] >> 24 == u32::from(slot)
        && event[3] & (0x1f << 16) == u32::from(dci) << 16
        && origin & !15 == pointer
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "completion_tests.rs"]
mod tests;
