//! One retained coherent page and one published bulk TD per endpoint.
//!
//! A token is a receipt, not ownership of hardware DMA. Dropping it or a
//! future awaiting it never makes the endpoint scratch page reusable.
//!
//! Isochronous endpoints hold an [`IsochPool`] instead of a single
//! [`State`]: up to [`ISOCH_PIPELINE_DEPTH`] TDs in flight at once
//! (#2060), each with its own owner state, so Transfer Events route
//! by originating TRB pointer to the slot that owns them.

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
    /// Originating TRB pointer. Serials are per-owner-state, so
    /// two isoch pipeline slots can hold the same serial at once;
    /// the TRB pointer is what disambiguates them (#2060).
    pub trb: u64,
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

    /// Originating TRB pointer of the retained TD, if any. The
    /// isoch pool routes tokens to slots by this pointer (#2060):
    /// ring positions are distinct while a TD is in flight, so it
    /// identifies the slot even when two slots hold the same
    /// per-state serial.
    pub(super) fn pending_trb(&self) -> Option<u64> {
        self.pending.as_ref().map(|pending| pending.trb)
    }

    /// Latch `event` into the retained TD's completion iff it
    /// pointer-matches that TD. Unlike [`State::record`], no
    /// stopping quarantine: the isoch pool applies quarantine
    /// only after no slot matched exactly, so a stopping TD never
    /// swallows a sibling's genuine completion (#2060).
    pub(super) fn record_exact(&mut self, event: super::event_wait::Event) -> bool {
        let Some(pending) = self.pending.as_mut() else {
            return false;
        };
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

    /// True when this state is mid-stop and `event` is a Transfer
    /// Event for the retained TD's endpoint: the event must be
    /// quarantined, never latched or queued. Stop Endpoint can
    /// force an event at the successor TRB, which a later TD would
    /// otherwise pointer-match after the ring address is reused.
    pub(super) fn quarantines(&self, event: &super::event_wait::Event) -> bool {
        let Some(pending) = self.pending.as_ref() else {
            return false;
        };
        pending.stopping
            && event[3] & (0x3f << 10) == 32 << 10
            && event[3] >> 24 == u32::from(pending.identity.slot)
            && event[3] & (0x1f << 16) == u32::from(pending.identity.dci) << 16
    }

    /// Drop the retained TD without a terminal completion. Only
    /// the isochronous stop coordinator may call this, after Set
    /// TR Dequeue Pointer proved the endpoint's whole posted
    /// pipeline hardware-dead: a stop retires every in-flight
    /// isoch TD on the endpoint, not just the token it was
    /// claimed for (#2060).
    pub(super) fn force_reset(&mut self) {
        self.pending = None;
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
            trb: p.trb,
        })
    }
    pub fn validate_stop(&self, id: StopIdentity) -> Result<(), Error> {
        let p = self.pending.as_ref().ok_or(Error::Stale)?;
        if !p.stopping
            || p.serial != id.serial
            || p.trb != id.trb
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

    /// Begin halt recovery for the retained TD. Mirrors the Stop
    /// coordinator's quarantine: while recovery runs, `record` keeps
    /// every Transfer Event for this endpoint out of the lossy global
    /// queues. Returns the stop identity when a TD is retained, or
    /// `None` when the endpoint is idle (recovery then degenerates to
    /// the bare hardware Reset Endpoint + Set Dequeue sequence).
    /// A token for the retained TD becomes stale the moment
    /// `finish_halt_recovery` clears `pending`.
    pub fn begin_halt_recovery(&mut self, generation: u64) -> Result<Option<StopIdentity>, Error> {
        let Some(p) = self.pending.as_mut() else {
            return Ok(None);
        };
        if generation == 0 || p.identity.generation != generation {
            return Err(Error::Stale);
        }
        if p.stopping {
            return Err(Error::Busy);
        }
        p.stopping = true;
        Ok(Some(StopIdentity {
            generation,
            serial: p.serial,
            slot: p.identity.slot,
            dci: p.identity.dci,
            trb: p.trb,
        }))
    }
    /// Only the completed Reset Endpoint + Set Dequeue coordinator may
    /// call this, after the output context readback showed the endpoint
    /// Stopped with the requested dequeue pointer and the endpoint's
    /// queued events were purged. Clears the retained TD; any token
    /// for it fails validation as stale from here on.
    pub fn finish_halt_recovery(&mut self, id: Option<StopIdentity>) -> Result<(), Error> {
        match id {
            Some(id) => {
                self.validate_stop(id)?;
                self.pending = None;
                Ok(())
            }
            None => {
                if self.pending.is_some() {
                    return Err(Error::Stale);
                }
                Ok(())
            }
        }
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

    /// Isochronous completion (#885): the same pointer-match,
    /// generation, and residue discipline as [`State::complete`],
    /// but a Short Packet (CC 13) is a normal outcome in *either*
    /// direction. An isoch OUT packet may be cut short by the
    /// device's per-frame budget and an isoch IN packet by the
    /// device sourcing fewer bytes than the buffer; xHCI 1.2
    /// §4.11.2.2 / §6.4.2.1 treats CC 13 on an Isoch TRB as a
    /// completed transfer, not an error. Bulk keeps its narrower
    /// rule (CC 13 only for IN) in `complete`.
    pub fn complete_isoch(
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
        if code != 1 && code != 13 {
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

/// Maximum concurrent isochronous TDs on one endpoint (#2060).
/// Matches the UVC pipelined pump's `ISOC_DEPTH` (4,
/// `narf_drivers_video::uvc`): the pump clamps the advertised
/// depth to the smaller of the two, so advertising more would
/// never be used and advertising fewer would waste pump slots.
/// One pool slot owns one 4 KiB DMA page in the endpoint state;
/// the pool itself holds only the owner states.
pub const ISOCH_PIPELINE_DEPTH: usize = 4;

/// Per-endpoint isochronous pipeline (#2060): one single-pending
/// owner state per in-flight TD, so up to
/// [`ISOCH_PIPELINE_DEPTH`] Isoch TDs can be posted on one
/// endpoint at once, each staging in its own DMA page (the
/// endpoint state holds one page per slot, indexed the same
/// way). Completion identity stays per-TD: Transfer Events
/// route by originating TRB pointer, and a stop retires the
/// whole pipeline — Set TR Dequeue Pointer moves the dequeue
/// past every posted TD, so siblings of a stopped TD are
/// hardware-dead too and their tokens go stale with it.
///
/// The pool never touches DMA itself: callers resolve a slot's
/// page from the token's slot ([`IsochPool::slot_of`]) and stage
/// through the publish closure of [`IsochPool::begin_on`].
#[derive(Debug)]
pub(super) struct IsochPool {
    slots: [State; ISOCH_PIPELINE_DEPTH],
}
impl IsochPool {
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| State::new()),
        }
    }

    /// Any TD in flight on this endpoint.
    pub fn active(&self) -> bool {
        self.slots.iter().any(State::active)
    }

    /// First slot with no TD in flight, if any. Advisory: the
    /// caller must still begin through [`IsochPool::begin_on`],
    /// which re-checks the slot is free and reports `Busy`.
    pub fn free_slot(&self) -> Option<usize> {
        self.slots.iter().position(|slot| !slot.active())
    }

    /// Slot holding `token`'s TD, by originating TRB pointer.
    /// `None` when no slot holds it (completed, retired, or a
    /// foreign token).
    pub fn slot_of(&self, token: &Token) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.pending_trb() == Some(token.trb))
    }

    /// Begin one TD in `slot` (see [`IsochPool::free_slot`]).
    /// Same contract as [`State::begin`]: the publish closure
    /// runs only after exclusive ownership is recorded, and a
    /// busy slot reports `Busy` without publishing.
    pub fn begin_on(
        &mut self,
        slot: usize,
        id: Endpoint,
        direction: Direction,
        length: usize,
        publish: impl FnOnce() -> u64,
    ) -> Result<Token, Error> {
        let state = self.slots.get_mut(slot).ok_or(Error::Stale)?;
        state.begin(id, direction, length, publish)
    }

    /// Route a Transfer Event to the slot whose TD it names.
    /// Exact pointer matches win over the stopping quarantine:
    /// a sibling's genuine completion latches even while another
    /// slot is mid-stop. Only when no slot matched does a
    /// stopping slot quarantine the event (Stop Endpoint can
    /// force one at a successor TRB).
    pub fn record(&mut self, event: super::event_wait::Event) -> bool {
        for slot in self.slots.iter_mut() {
            if slot.record_exact(event) {
                return true;
            }
        }
        self.slots.iter().any(|slot| slot.quarantines(&event))
    }

    pub fn take_matching(
        &mut self,
        predicate: &mut dyn FnMut(&super::event_wait::Event) -> bool,
    ) -> Result<Option<super::event_wait::Event>, Error> {
        for slot in self.slots.iter_mut() {
            if let Some(event) = slot.take_matching(predicate)? {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }

    /// Route validation to the slot holding `token`'s TD.
    pub fn validate(&self, generation: u64, token: &Token) -> Result<(), Error> {
        let slot = self.slot_of(token).ok_or(Error::Stale)?;
        self.slots[slot].validate(generation, token)
    }

    /// Complete `token`'s TD from its slot's owner state, same
    /// isoch discipline as [`State::complete_isoch`].
    pub fn complete_isoch(
        &mut self,
        generation: u64,
        token: &Token,
        event: &[u32; 4],
        consume: impl FnOnce(usize),
    ) -> Result<Option<usize>, Error> {
        let slot = self.slot_of(token).ok_or(Error::Stale)?;
        self.slots[slot].complete_isoch(generation, token, event, consume)
    }

    /// Route a stop claim to the slot holding `token`'s TD.
    pub fn begin_stop(&mut self, generation: u64, token: &Token) -> Result<StopIdentity, Error> {
        let slot = self.slot_of(token).ok_or(Error::Stale)?;
        self.slots[slot].begin_stop(generation, token)
    }

    pub fn validate_stop(&self, id: StopIdentity) -> Result<(), Error> {
        let slot = self
            .slots
            .iter()
            .position(|slot| slot.pending_trb() == Some(id.trb))
            .ok_or(Error::Stale)?;
        self.slots[slot].validate_stop(id)
    }

    /// Finish a stop: validate the claimed identity, release its
    /// TD, then release every sibling TD too. Set TR Dequeue
    /// Pointer proved the endpoint's dequeue past all posted
    /// TDs, so the siblings are hardware-dead — their tokens go
    /// stale and their waiters report the timeout, never a late
    /// completion aliased onto a future transfer.
    pub fn finish_stop(&mut self, id: StopIdentity) -> Result<(), Error> {
        let slot = self
            .slots
            .iter()
            .position(|slot| slot.pending_trb() == Some(id.trb))
            .ok_or(Error::Stale)?;
        self.slots[slot].finish_stop(id)?;
        for slot in self.slots.iter_mut() {
            slot.force_reset();
        }
        Ok(())
    }
}

/// Serialize the shared EP0 scratch page. An error or dropped operation does
/// not call complete, so the claim remains terminally busy until one of the
/// two recovery coordinators (halt recovery, timeout cancellation) proves
/// the hardware side dead and calls `force_reset`.
///
/// A control TD retains up to three receipts. `expected` holds the Data
/// and Status Stage TRBs, whose IOC events must both be consumed before
/// the claim completes. `setup` names the Setup Stage TRB: it requests no
/// event of its own, so a Transfer Event against it is always an error
/// (the xHC reports a failed SETUP transaction, or a stall, at the TRB it
/// was executing). Retaining it keeps that event out of the lossy shared
/// queue so the waiter can end the TD on it, as Linux `process_ctrl_td`
/// does for an error on any TRB of the TD.
#[derive(Debug)]
pub(super) struct ControlState {
    busy: bool,
    /// Timeout cancellation in progress: every EP0 Transfer Event for the
    /// slot is quarantined (Stop Endpoint may force one at any TRB) and
    /// no waiter may take a retained event.
    cancelling: bool,
    setup: Option<(u64, super::completion::Latch)>,
    expected: [Option<(u64, super::completion::Latch)>; 2],
}
impl ControlState {
    pub const fn new() -> Self {
        Self {
            busy: false,
            cancelling: false,
            setup: None,
            expected: [None, None],
        }
    }
    pub fn active(&self) -> bool {
        self.busy
    }
    /// Drop the EP0 claim without a terminal completion. Only the
    /// recovery coordinators may call this: halt recovery after the
    /// Reset Endpoint command for DCI 1 completed successfully, or
    /// timeout cancellation after Stop Endpoint (or Reset Endpoint,
    /// when the pipe had halted) completed — and in both cases only
    /// after Set TR Dequeue Pointer moved the dequeue past the TD and
    /// the endpoint's output context read back Stopped at that
    /// pointer. At that point the retained TD is hardware-dead, and
    /// any waiter on its latches times out instead of completing
    /// against a reset pipe. This is the one sanctioned exception to
    /// the "an error does not call complete" rule above — the
    /// hardware state it guards no longer exists.
    pub fn force_reset(&mut self) {
        self.busy = false;
        self.cancelling = false;
        self.setup = None;
        self.expected = [None, None];
    }
    pub fn begin(&mut self, actual: u64, expected: u64) -> Result<(), Error> {
        if actual == 0 || actual != expected {
            return Err(Error::Stale);
        }
        if self.busy {
            return Err(Error::Busy);
        }
        self.busy = true;
        self.cancelling = false;
        self.setup = None;
        self.expected = [None, None];
        Ok(())
    }
    /// Retain the Setup Stage TRB of the claimed TD. Its receipt is
    /// error-only: `complete` never requires it to be consumed.
    pub fn expect_setup(&mut self, pointer: u64) -> Result<(), Error> {
        if !self.busy {
            return Err(Error::Stale);
        }
        if self.setup.is_some() {
            return Err(Error::Busy);
        }
        self.setup = Some((pointer, super::completion::Latch::new()));
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
    /// Begin timeout cancellation of the retained TD. From here until
    /// `force_reset`, `record` quarantines every EP0 Transfer Event
    /// for the slot and `take_matching` yields nothing. An idle pipe
    /// has nothing to cancel.
    pub fn begin_cancel(&mut self, actual: u64, expected: u64) -> Result<(), Error> {
        if actual == 0 || actual != expected || !self.busy {
            return Err(Error::Stale);
        }
        if self.cancelling {
            return Err(Error::Busy);
        }
        self.cancelling = true;
        Ok(())
    }
    pub fn record(&mut self, slot: u8, event: super::event_wait::Event) -> bool {
        if self.cancelling {
            // Stop Endpoint can force an event at any TRB of the TD or
            // at its successor. None may enter the lossy global queue.
            return event[3] & (0x3f << 10) == 32 << 10
                && event[3] >> 24 == u32::from(slot)
                && event[3] & (0x1f << 16) == 1 << 16;
        }
        for (pointer, completion) in self
            .setup
            .iter_mut()
            .chain(self.expected.iter_mut().flatten())
        {
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
        if self.cancelling {
            return Ok(None);
        }
        for (_, completion) in self
            .setup
            .iter_mut()
            .chain(self.expected.iter_mut().flatten())
        {
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
        if self.cancelling
            || !self
                .expected
                .iter()
                .flatten()
                .all(|(_, completion)| completion.consumed())
        {
            return Err(Error::Busy);
        }
        self.busy = false;
        self.setup = None;
        self.expected = [None, None];
        Ok(())
    }
    /// Cold-path diagnostics: the retained receipts as
    /// `(TRB pointer, latched event)` — Setup first, then Data/Status in
    /// publication order. Does not consume anything.
    pub fn receipts(&self) -> [Option<(u64, Option<super::event_wait::Event>)>; 3] {
        let mut out = [None; 3];
        for (entry, (pointer, completion)) in out
            .iter_mut()
            .zip(self.setup.iter().chain(self.expected.iter().flatten()))
        {
            *entry = Some((*pointer, completion.peek()));
        }
        out
    }
}

/// Address attempts reserve a generation before publishing any device DMA;
/// published/retired generations never silently return to the unused state.
/// The single sanctioned return path is `reclaim`: the explicit
/// stop/drain/removal API (`Xhci::reclaim_slot`) drives a slot through
/// Disable Slot completion, hardware-event drain, queued-event purge and
/// DMA release first, and only then calls `reclaim` to make the slot id
/// allocatable again. A reclaimed slot is always re-addressed under a
/// fresh, never-before-used generation (the controller-global generation
/// counter is monotonic), so a stale handle can never match it.
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
        if !self.is_unused(slot) {
            return Err(Error::Busy);
        }
        self.generations[usize::from(slot)] = generation;
        Ok(())
    }
    pub fn is_unused(&self, slot: u8) -> bool {
        slot != 0 && self.generations[usize::from(slot)] == 0
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
    /// A slot is retired once `retire` has run (Disable Slot path) and
    /// it has not yet been reclaimed. Only retired slots may reclaim.
    pub fn is_retired(&self, slot: u8) -> bool {
        slot != 0 && self.generations[usize::from(slot)] == u64::MAX
    }
    /// Return a retired slot to the unused state so a later `begin`
    /// (under a fresh generation) may reserve it again. The caller
    /// (`Xhci::reclaim_slot`) must already have proven the hardware
    /// side quiesced: Disable Slot completed, the slot's queued and
    /// in-ring events drained/purged, and every DMA page the slot
    /// owned released. Reclaiming a live or unused slot is refused.
    pub fn reclaim(&mut self, slot: u8) -> Result<(), Error> {
        if !self.is_retired(slot) {
            return Err(Error::Stale);
        }
        self.generations[usize::from(slot)] = 0;
        Ok(())
    }
    /// Mark every slot retired. Controller recovery calls this before
    /// the hardware reset so any operation still holding a generation
    /// fails its next `matches` check instead of completing against a
    /// controller whose state is about to be wiped.
    pub fn invalidate_all(&mut self) {
        for generation in self.generations.iter_mut() {
            if *generation != 0 {
                *generation = u64::MAX;
            }
        }
    }
    /// Clear every slot back to unused. Only valid after a completed
    /// hardware reset with all per-slot DMA already released — the
    /// recovery counterpart of `reclaim`, for all slots at once.
    pub fn reset(&mut self) {
        self.generations = [0; 256];
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
