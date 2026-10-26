//! Bounded sequence ordering for original native MPDUs before CCMP/PN.
//! The driver owns BA negotiation, peer/TID identity, PHY/CRC admission,
//! current key epochs and every delivery decision. An item here is opaque;
//! releasing it grants no key, port, policy or radio authority.
use alloc::vec::Vec;

const MASK: u16 = 4095;
const HALF: usize = 2048;
pub const MAX_WINDOW: u8 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Window,
    Timeout,
    Sequence,
    Allocation,
}

struct Entry<T> {
    arrived: u64,
    item: T,
}

/// One current native peer/TID BA session's bounded12-bit sequence window.
///
/// `new` deliberately has no invented ADDBA SSN. The first validated native
/// MPDU initializes the head, as mac80211's offloaded RX BA auto_seq does.
/// A separately validated BAR may establish or advance it explicitly.
/// Drivers must order original encrypted MPDUs here, then authenticate/replay
/// check only the released items. Clear on key/reply, peer or session retirement
/// according to the native ownership contract; do not carry old epochs into a
/// fresh key. Drop/clear only discard ownership and never deliver anything.
pub struct Reorder<T> {
    slots: Vec<Option<Entry<T>>>,
    head_sequence: Option<u16>,
    head_slot: usize,
    buffered: usize,
    timeout_ns: u64,
}

impl<T> core::fmt::Debug for Reorder<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reorder")
            .field("window", &self.window())
            .field("head", &self.head())
            .field("buffered", &self.buffered)
            .finish_non_exhaustive()
    }
}

fn distance(sequence: u16, head: u16) -> usize {
    usize::from(sequence.wrapping_sub(head) & MASK)
}

impl<T> Reorder<T> {
    pub fn new(window: u8, timeout_ns: u64) -> Result<Self, Error> {
        if !(1..=MAX_WINDOW).contains(&window) {
            return Err(Error::Window);
        }
        if timeout_ns == 0 {
            return Err(Error::Timeout);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(usize::from(window))
            .map_err(|_| Error::Allocation)?;
        slots.resize_with(usize::from(window), || None);
        Ok(Self {
            slots,
            head_sequence: None,
            head_slot: 0,
            buffered: 0,
            timeout_ns,
        })
    }
    pub fn window(&self) -> u8 {
        self.slots.len() as u8
    }
    pub fn head(&self) -> Option<u16> {
        self.head_sequence
    }
    pub fn buffered(&self) -> usize {
        self.buffered
    }
    fn output(&self, extra: usize) -> Result<Vec<T>, Error> {
        let mut output = Vec::new();
        output
            .try_reserve_exact(self.buffered + extra)
            .map_err(|_| Error::Allocation)?;
        Ok(output)
    }
    fn move_head(&mut self, count: usize) {
        if let Some(head) = self.head_sequence {
            self.head_sequence = Some(head.wrapping_add(count as u16) & MASK);
            self.head_slot = (self.head_slot + count % self.slots.len()) % self.slots.len();
        }
    }
    fn take_head(&mut self, output: &mut Vec<T>) {
        if let Some(entry) = self.slots[self.head_slot].take() {
            self.buffered -= 1;
            output.push(entry.item);
        }
        self.move_head(1);
    }
    fn advance_by(&mut self, count: usize, output: &mut Vec<T>) {
        // At most one bounded window needs examination. Everything farther
        // ahead is an empty gap and can advance arithmetically, including
        // non-power-of-two windows across4095→0.
        let examined = count.min(self.slots.len());
        for _ in 0..examined {
            self.take_head(output);
        }
        self.move_head(count - examined);
    }
    fn contiguous(&mut self, output: &mut Vec<T>) {
        while self.buffered != 0 && self.slots[self.head_slot].is_some() {
            self.take_head(output);
        }
    }
    fn expire_into(&mut self, now_ns: u64, output: &mut Vec<T>) {
        while self.buffered != 0 {
            let oldest = self
                .slots
                .iter()
                .flatten()
                .map(|entry| entry.arrived)
                .min()
                .unwrap();
            if now_ns.saturating_sub(oldest) < self.timeout_ns {
                break;
            }
            // A hole cannot hold an older buffered MPDU beyond its timeout
            // merely because a nearer sequence arrived more recently. Release
            // the earliest buffered sequence, then its contiguous successors.
            let offset = (0..self.slots.len())
                .find(|offset| self.slots[(self.head_slot + offset) % self.slots.len()].is_some())
                .unwrap();
            self.advance_by(offset, output);
            self.contiguous(output);
        }
    }
    /// Insert one original, fully native-admitted MPDU. The returned vector
    /// contains sequence-ordered ownership only; the caller must authenticate
    /// each item and recheck current publication authority afterward.
    ///
    /// Duplicate/old and exactly-half-range-ambiguous input drops its incoming
    /// item without replacing buffered content or refreshing its age. A future
    /// sequence outside the window releases older buffered items in order and
    /// advances through holes just enough to include that sequence.
    /// `now_ns` comes from the driver's monotonic clock. Every push also drives
    /// hole expiry; use `expire` during idle periods. Allocation failure keeps
    /// all previously buffered ownership unchanged and drops only this input.
    pub fn push(&mut self, sequence: u16, now_ns: u64, item: T) -> Result<Vec<T>, Error> {
        if sequence > MASK {
            return Err(Error::Sequence);
        }
        let mut output = self.output(1)?;
        self.expire_into(now_ns, &mut output);
        let head = match self.head_sequence {
            Some(head) => head,
            None => {
                self.head_sequence = Some(sequence);
                sequence
            }
        };
        let ahead = distance(sequence, head);
        if ahead >= HALF {
            return Ok(output);
        }
        if ahead >= self.slots.len() {
            self.advance_by(ahead - self.slots.len() + 1, &mut output);
        }
        let offset = distance(sequence, self.head_sequence.unwrap());
        let index = (self.head_slot + offset) % self.slots.len();
        if self.slots[index].is_none() {
            self.slots[index] = Some(Entry {
                arrived: now_ns,
                item,
            });
            self.buffered += 1;
        }
        self.contiguous(&mut output);
        Ok(output)
    }
    /// Release expired holes without receiving another frame. A clock value
    /// earlier than an arrival cannot expire it. No callback or key work runs.
    pub fn expire(&mut self, now_ns: u64) -> Result<Vec<T>, Error> {
        let mut output = self.output(0)?;
        self.expire_into(now_ns, &mut output);
        Ok(output)
    }
    /// Apply a separately native-validated BAR/new head. Older buffered items
    /// are released in sequence order across holes, followed by contiguous
    /// items at the new head. Old/half-range-ambiguous BARs cannot move backward.
    /// No peer/TID/RA/TA validation is implied by this sequence-only operation.
    pub fn advance(&mut self, sequence: u16, now_ns: u64) -> Result<Vec<T>, Error> {
        if sequence > MASK {
            return Err(Error::Sequence);
        }
        let mut output = self.output(0)?;
        self.expire_into(now_ns, &mut output);
        if let Some(head) = self.head_sequence {
            let ahead = distance(sequence, head);
            if ahead < HALF {
                self.advance_by(ahead, &mut output);
                self.contiguous(&mut output);
            }
        } else {
            self.head_sequence = Some(sequence);
        }
        Ok(output)
    }
    /// Discard every buffered item and return to offloaded-BA auto-sequence.
    /// Existing allocation is retained; no buffered bytes are delivered.
    pub fn clear(&mut self) {
        for slot in &mut self.slots {
            *slot = None;
        }
        self.buffered = 0;
        self.head_sequence = None;
        self.head_slot = 0;
    }
    /// Consume the session without releasing any buffered item to its caller.
    pub fn retire(mut self) {
        self.clear();
    }
}

#[cfg(feature = "kernel-test")]
#[path = "reorder_tests.rs"]
mod tests;
