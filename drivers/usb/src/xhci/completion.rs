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
}
/// At most one retained receipt per physical command-ring entry.
/// A waiter that times out retires its own receipt (#884):
/// `retire_pointer` drops the reservation and records the TRB
/// pointer as retired, so a Command Completion Event that arrives
/// late for it is swallowed by `record` instead of landing in the
/// lossy command-event queue, where it could be misattributed to
/// the next command recycled onto the same ring entry.
/// Re-reserving the entry clears the tombstone — a later CCE
/// naming the pointer then belongs to the new command. Residual
/// race, inherent to the xHCI event format: a CCE carries no
/// sequence number, so one that arrives after re-reserve but
/// before the new command completes is indistinguishable from the
/// new command's own CCE.
pub(super) struct Commands {
    pending: Vec<Option<Command>>,
    retired: Vec<u64>,
}
impl Commands {
    pub fn new(entries: usize) -> Self {
        Self {
            pending: core::iter::repeat_with(|| None).take(entries).collect(),
            retired: Vec::new(),
        }
    }
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
        // Ring pointers repeat after the reset cursors restart at
        // zero: a stale tombstone would swallow the recycled
        // entry's own completion, so recovery drops them too.
        self.retired.clear();
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
        });
        // The entry is live again: a later CCE naming this pointer
        // belongs to the new command, not the retired one.
        self.retired.retain(|retired| *retired != pointer);
        Ok(())
    }
    /// Retire the receipt for a command whose waiter timed out
    /// (#884) and remember its TRB pointer so a late CCE for it
    /// is swallowed by `record`. Returns whether a receipt was
    /// dropped; false when the pointer was already consumed or
    /// never reserved. Pointers are unique per ring entry, so at
    /// most one receipt matches.
    pub fn retire_pointer(&mut self, pointer: u64) -> bool {
        for value in self.pending.iter_mut() {
            if value
                .as_ref()
                .is_some_and(|command| command.pointer == pointer)
            {
                *value = None;
                if !self.retired.contains(&pointer) {
                    self.retired.push(pointer);
                }
                return true;
            }
        }
        false
    }
    pub fn record(&mut self, event: Event) -> bool {
        // A CCE for a retired pointer arrived after its waiter
        // gave up: swallow it here so the demux does not queue it,
        // where it could be misattributed to the next command
        // recycled onto the same ring entry.
        let origin = u64::from(event[0]) | u64::from(event[1]) << 32;
        if self.retired.contains(&(origin & !15)) {
            return true;
        }
        for command in self.pending.iter_mut().flatten() {
            if super::event_wait::command_pointer_matches(&event, command.pointer)
                && (command.slot == 0 || event[3] >> 24 == u32::from(command.slot))
            {
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
                if let Some(event) = command.completion.take_matching(predicate)? {
                    *value = None;
                    return Ok(Some(event));
                }
            }
        }
        Ok(None)
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
