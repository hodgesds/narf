//! One retained coherent page and one published bulk TD per endpoint.
//!
//! A token is a receipt, not ownership of hardware DMA. Dropping it or a
//! future awaiting it never makes the endpoint scratch page reusable.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    BadLength,
    Stale,
    Exhausted,
    Malformed,
    Completion(u8),
}

#[derive(Debug)]
pub struct Token {
    generation: u64,
    serial: u64,
    slot: u8,
    endpoint: u8,
    trb: u64,
    length: usize,
    direction: Direction,
}
impl Token {
    pub(crate) fn slot(&self) -> u8 {
        self.slot
    }
    pub(super) fn endpoint(&self) -> u8 {
        self.endpoint
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(super) fn length(&self) -> usize {
        self.length
    }
    pub(super) fn direction(&self) -> Direction {
        self.direction
    }
    pub(super) fn matches(&self, event: &[u32; 4]) -> bool {
        let pointer = u64::from(event[0]) | u64::from(event[1]) << 32;
        event[3] & (0x3f << 10) == 32 << 10
            && event[3] & (1 << 2) == 0 // This TD never uses Event Data.
            && event[3] >> 24 == u32::from(self.slot)
            && event[3] & (0x1f << 16) == u32::from(self.endpoint) << 16
            && pointer & !15 == self.trb
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Endpoint {
    pub generation: u64,
    pub slot: u8,
    pub dci: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StopIdentity {
    pub generation: u64,
    pub serial: u64,
    pub slot: u8,
    pub dci: u8,
}

#[derive(Debug)]
struct Pending {
    identity: Endpoint,
    completion: super::completion::Latch,
    serial: u64,
    trb: u64,
    poisoned: bool,
    stopping: bool,
}

#[derive(Debug)]
pub(super) struct State {
    next: u64,
    pending: Option<Pending>,
}
impl State {
    pub const fn new() -> Self {
        Self {
            next: 1,
            pending: None,
        }
    }
    pub fn active(&self) -> bool {
        self.pending.is_some()
    }

    /// The infallible publication closure runs only after exclusive scratch
    /// ownership is recorded. No await or fallible work may be hidden inside
    /// it; configuration, length and address checks must precede begin.
    pub fn begin(
        &mut self,
        id: Endpoint,
        direction: Direction,
        length: usize,
        publish: impl FnOnce() -> u64,
    ) -> Result<Token, Error> {
        if self.active() {
            return Err(Error::Busy);
        }
        let Endpoint {
            generation,
            slot,
            dci: endpoint,
        } = id;
        if generation == 0 || slot == 0 || !(2..=31).contains(&endpoint) {
            return Err(Error::Stale);
        }
        if !(1..=4096).contains(&length) {
            return Err(Error::BadLength);
        }
        let serial = self.next;
        self.next = self.next.checked_add(1).ok_or(Error::Exhausted)?;
        self.pending = Some(Pending {
            identity: id,
            completion: super::completion::Latch::new(),
            serial,
            trb: 0,
            poisoned: false,
            stopping: false,
        });
        let trb = publish();
        self.pending.as_mut().unwrap().trb = trb;
        Ok(Token {
            generation,
            serial,
            slot,
            endpoint,
            trb,
            length,
            direction,
        })
    }

    /// Called by ISR demux before the lossy shared queues, under the
    /// controller's device ownership lock. It must never skip a busy lock.
    pub fn record(&mut self, event: super::event_wait::Event) -> bool {
        let Some(pending) = self.pending.as_mut() else {
            return false;
        };
        if pending.stopping
            && event[3] & (0x3f << 10) == 32 << 10
            && event[3] >> 24 == u32::from(pending.identity.slot)
            && event[3] & (0x1f << 16) == u32::from(pending.identity.dci) << 16
        {
            // Stop can force an event at the successor (not the old token)
            // TRB. Quarantine all this endpoint's TEs until Stop+SetDequeue
            // retire the old schedule; none may enter the lossy global queue.
            return true;
        }
        if super::completion::transfer_matches(
            &event,
            pending.identity.slot,
            pending.identity.dci,
            pending.trb,
        ) {
            pending.completion.record(event);
            true
        } else {
            false
        }
    }
    pub fn take_matching(
        &mut self,
        predicate: &mut dyn FnMut(&super::event_wait::Event) -> bool,
    ) -> Result<Option<super::event_wait::Event>, Error> {
        let Some(pending) = self.pending.as_mut() else {
            return Ok(None);
        };
        if pending.stopping {
            return Ok(None);
        }
        pending.completion.take_matching(predicate).map_err(|_| {
            pending.poisoned = true;
            Error::Malformed
        })
    }

    pub fn validate(&self, generation: u64, token: &Token) -> Result<(), Error> {
        let pending = self.pending.as_ref().ok_or(Error::Stale)?;
        if generation != token.generation
            || pending.identity.generation != generation
            || pending.identity.slot != token.slot
            || pending.identity.dci != token.endpoint
            || pending.serial != token.serial
            || pending.trb != token.trb
        {
            return Err(Error::Stale);
        }
        if pending.stopping {
            return Err(Error::Busy);
        }
        if pending.poisoned || pending.completion.conflicted() {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    pub fn begin_stop(&mut self, generation: u64, token: &Token) -> Result<StopIdentity, Error> {
        let p = self.pending.as_mut().ok_or(Error::Stale)?;
        if generation != token.generation || p.serial != token.serial || p.trb != token.trb {
            return Err(Error::Stale);
        }
        if p.stopping {
            return Err(Error::Busy);
        }
        p.stopping = true;
        Ok(StopIdentity {
            generation,
            serial: p.serial,
            slot: p.identity.slot,
            dci: p.identity.dci,
        })
    }
    pub fn validate_stop(&self, id: StopIdentity) -> Result<(), Error> {
        let p = self.pending.as_ref().ok_or(Error::Stale)?;
        if !p.stopping
            || p.serial != id.serial
            || p.identity.generation != id.generation
            || p.identity.slot != id.slot
            || p.identity.dci != id.dci
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Only the completed Stop+SetDequeue coordinator may call this after
    /// context verification and quarantined event-queue removal.
    pub fn finish_stop(&mut self, id: StopIdentity) -> Result<(), Error> {
        self.validate_stop(id)?;
        self.pending = None;
        Ok(())
    }

    /// A caller can poll indefinitely without imposing a timeout that drops
    /// the TD. Completion data is copied before reopening the scratch page.
    pub fn complete(
        &mut self,
        generation: u64,
        token: &Token,
        event: &[u32; 4],
        consume: impl FnOnce(usize),
    ) -> Result<Option<usize>, Error> {
        self.validate(generation, token)?;
        if !token.matches(event) {
            return Ok(None);
        }
        let code = (event[2] >> 24) as u8;
        if code != 1 && !(code == 13 && token.direction == Direction::In) {
            self.pending.as_mut().unwrap().poisoned = true;
            return Err(Error::Completion(code));
        }
        let residue = (event[2] & 0xff_ffff) as usize;
        if residue > token.length {
            self.pending.as_mut().unwrap().poisoned = true;
            return Err(Error::Malformed);
        }
        let transferred = token.length - residue;
        consume(transferred);
        self.pending = None;
        Ok(Some(transferred))
    }
}

/// Serialize the shared EP0 scratch page. An error or dropped operation does
/// not call complete, so the claim remains terminally busy.
#[derive(Debug)]
pub(super) struct ControlState {
    busy: bool,
    expected: [Option<(u64, super::completion::Latch)>; 2],
}
impl ControlState {
    pub const fn new() -> Self {
        Self {
            busy: false,
            expected: [None, None],
        }
    }
    pub fn active(&self) -> bool {
        self.busy
    }
    pub fn begin(&mut self, actual: u64, expected: u64) -> Result<(), Error> {
        if actual == 0 || actual != expected {
            return Err(Error::Stale);
        }
        if self.busy {
            return Err(Error::Busy);
        }
        self.busy = true;
        self.expected = [None, None];
        Ok(())
    }
    pub fn expect(&mut self, pointer: u64) -> Result<(), Error> {
        if !self.busy {
            return Err(Error::Stale);
        }
        let empty = self
            .expected
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(Error::Busy)?;
        *empty = Some((pointer, super::completion::Latch::new()));
        Ok(())
    }
    pub fn record(&mut self, slot: u8, event: super::event_wait::Event) -> bool {
        for (pointer, completion) in self.expected.iter_mut().flatten() {
            if super::completion::transfer_matches(&event, slot, 1, *pointer) {
                completion.record(event);
                return true;
            }
        }
        false
    }
    pub fn take_matching(
        &mut self,
        predicate: &mut dyn FnMut(&super::event_wait::Event) -> bool,
    ) -> Result<Option<super::event_wait::Event>, Error> {
        for (_, completion) in self.expected.iter_mut().flatten() {
            if let Some(event) = completion
                .take_matching(predicate)
                .map_err(|_| Error::Malformed)?
            {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }
    pub fn complete(&mut self, actual: u64, expected: u64) -> Result<(), Error> {
        if actual == 0 || actual != expected || !self.busy {
            return Err(Error::Stale);
        }
        if !self
            .expected
            .iter()
            .flatten()
            .all(|(_, completion)| completion.consumed())
        {
            return Err(Error::Busy);
        }
        self.busy = false;
        self.expected = [None, None];
        Ok(())
    }
}

/// Slot reuse requires a future explicit controller stop/drain/removal API.
/// Address attempts reserve a generation before publishing any device DMA;
/// published/retired generations never silently return to the unused state.
pub(super) struct Slots {
    generations: [u64; 256],
}
impl Slots {
    pub const fn new() -> Self {
        Self {
            generations: [0; 256],
        }
    }
    pub fn begin(&mut self, slot: u8, generation: u64) -> Result<(), Error> {
        if slot == 0 || generation == 0 || generation == u64::MAX {
            return Err(Error::Stale);
        }
        if self.generations[usize::from(slot)] != 0 {
            return Err(Error::Busy);
        }
        self.generations[usize::from(slot)] = generation;
        Ok(())
    }
    pub fn matches(&self, slot: u8, generation: u64) -> bool {
        generation != 0 && self.generations[usize::from(slot)] == generation
    }
    pub fn release_unpublished(&mut self, slot: u8, generation: u64) {
        if self.matches(slot, generation) {
            self.generations[usize::from(slot)] = 0;
        }
    }
    pub fn any_reserved(&self) -> bool {
        self.generations.iter().any(|generation| *generation != 0)
    }
    pub fn retire(&mut self, slot: u8) {
        self.generations[usize::from(slot)] = u64::MAX;
    }
}

pub(super) fn command_pointer_matches(event: &[u32; 4], trb: u64) -> bool {
    let pointer = u64::from(event[0]) | u64::from(event[1]) << 32;
    event[3] & (0x3f << 10) == 33 << 10 && pointer & !15 == trb
}

pub(super) fn command_matches(event: &[u32; 4], slot: u8, trb: u64) -> bool {
    command_pointer_matches(event, trb) && event[3] >> 24 == u32::from(slot)
}

/// Input Context and new endpoint rings are ordinary CPU-owned resources
/// before command publication. After publication only a validated terminal
/// success may adopt them; cancellation/error must retain them indefinitely.
/// This is bounded to one poisoned configuration attempt per device.
pub(super) struct CommandDma<T> {
    resources: Option<T>,
    published: bool,
}
impl<T> CommandDma<T> {
    pub fn new(resources: T) -> Self {
        Self {
            resources: Some(resources),
            published: false,
        }
    }
    pub fn publish(&mut self) {
        self.published = true;
    }
    pub fn complete(mut self) -> T {
        self.resources.take().unwrap()
    }
}
impl<T> Drop for CommandDma<T> {
    fn drop(&mut self) {
        if self.published {
            if let Some(resources) = self.resources.take() {
                core::mem::forget(resources);
            }
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "bulk_owner_tests.rs"]
mod tests;
