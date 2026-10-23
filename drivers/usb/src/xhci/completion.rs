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
/// At most one retained receipt per physical command-ring entry. A dropped
/// waiter leaves its receipt reserved; new commands cannot overwrite it.
pub(super) struct Commands {
    pending: Vec<Option<Command>>,
}
impl Commands {
    pub fn new(entries: usize) -> Self {
        Self {
            pending: core::iter::repeat_with(|| None).take(entries).collect(),
        }
    }
    pub fn active(&self) -> bool {
        self.pending.iter().any(Option::is_some)
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
        Ok(())
    }
    pub fn record(&mut self, event: Event) -> bool {
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
