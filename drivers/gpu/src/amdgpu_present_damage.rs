//! Which rows of a CPU-copying presenter's staged scanout buffers already
//! hold a dumb framebuffer's current contents, so a DIRTYFB frame copies
//! only the rows that changed since the buffer it is copied into last held
//! that framebuffer (its own damage, and every later frame's).
//!
//! Buffers are named by address. Anything the presenter does not account
//! for (another framebuffer, a GEM or tiled copy, a surface reallocated or
//! written elsewhere, which the caller reports as a new `epoch`, or a
//! failed present) leaves rows unknown, and unknown rows are copied.
use alloc::vec::Vec;
use core::ops::Range;

/// A dumb framebuffer's rows as a presenter copies them: frames of one
/// source share their contents outside a frame's damage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    pub phys: u64,
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    /// Byte offset of the first copied pixel.
    pub offset: u64,
}

/// The covering span of two row ranges.
pub fn span(a: &Range<u32>, b: &Range<u32>) -> Range<u32> {
    if a.is_empty() {
        b.clone()
    } else if b.is_empty() {
        a.clone()
    } else {
        a.start.min(b.start)..a.end.max(b.end)
    }
}

/// A frame's damage after it replaced a waiting one of `old` (never copied):
/// both frames' rows of one source, else every row (None).
pub fn coalesce(
    old: (Option<Source>, Option<&Range<u32>>),
    next: (Option<Source>, Option<&Range<u32>>),
) -> Option<Range<u32>> {
    match (old, next) {
        ((Some(a), Some(x)), (Some(b), Some(y))) if a == b => Some(span(x, y)),
        _ => None,
    }
}

#[derive(Clone, Debug)]
struct Held {
    buffer: u64,
    source: Source,
    /// Rows that changed since the buffer was written.
    stale: Range<u32>,
}

/// What the staged buffers hold.
#[derive(Debug, Default)]
pub struct Damage {
    held: Vec<Held>,
    epoch: u64,
}
impl Damage {
    pub const fn new() -> Self {
        Self {
            held: Vec::new(),
            epoch: 0,
        }
    }
    /// The rows of a `source` frame damaged in `damage` (None: all) to copy
    /// into the buffer at `buffer` under surface `epoch`.
    pub fn plan(
        &self,
        source: Option<Source>,
        damage: Option<&Range<u32>>,
        buffer: u64,
        epoch: u64,
    ) -> Range<u32> {
        let Some(source) = source else {
            return 0..0;
        };
        let all = 0..source.height;
        let Some(rows) = damage else {
            return all;
        };
        if epoch != self.epoch {
            return all;
        }
        match self
            .held
            .iter()
            .find(|h| h.buffer == buffer && h.source == source)
        {
            Some(h) => {
                let rows = span(&h.stale, rows);
                rows.start.min(source.height)..rows.end.min(source.height)
            }
            None => all,
        }
    }
    /// A frame flipped to the front: a `source` frame damaged in `damage`
    /// (None: all rows), or a GEM or tiled frame (`source` None), copied
    /// into `written` (None: scanned out in place) under surface `epoch`.
    pub fn presented(
        &mut self,
        source: Option<Source>,
        damage: Option<&Range<u32>>,
        written: Option<u64>,
        epoch: u64,
    ) {
        if epoch != self.epoch {
            self.held.clear();
            self.epoch = epoch;
        }
        match source {
            Some(source) => {
                let rows = damage.cloned().unwrap_or(0..source.height);
                // Another source's buffers are not followed across frames.
                self.held.retain(|h| h.source == source);
                for h in &mut self.held {
                    h.stale = span(&h.stale, &rows);
                }
            }
            None => self.held.clear(),
        }
        if let Some(buffer) = written {
            self.held.retain(|h| h.buffer != buffer);
            if let Some(source) = source {
                self.held.push(Held {
                    buffer,
                    source,
                    stale: 0..0,
                });
            }
        }
    }
    /// No buffer's contents are known.
    pub fn forget(&mut self) {
        self.held.clear();
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    const A: u64 = 0x1000_0000;
    const B: u64 = 0x2000_0000;
    const C: u64 = 0x3000_0000;
    fn source(phys: u64) -> Option<Source> {
        Some(Source {
            phys,
            pitch: 64,
            width: 16,
            height: 100,
            offset: 0,
        })
    }

    fn damage_copies_only_what_each_buffer_lacks() -> TestResult {
        let s = source(0x8000_0000);
        let mut d = Damage::new();
        // Nothing is known yet: every row of a damaged frame.
        if d.plan(s, Some(&(10..20)), B, 0) != (0..100) {
            return TestResult::Fail("unknown buffer took a partial copy");
        }
        d.presented(s, Some(&(10..20)), Some(B), 0);
        // A (the old front) never held the source.
        if d.plan(s, Some(&(10..20)), A, 0) != (0..100) {
            return TestResult::Fail("buffer from before the source took a partial copy");
        }
        d.presented(s, Some(&(10..20)), Some(A), 0);
        // B holds the first frame: it lacks the second's and third's rows.
        if d.plan(s, Some(&(30..40)), B, 0) != (10..40) {
            return TestResult::Fail("partial copy is not both frames' damage");
        }
        // Another source, a full frame or a new epoch copies every row.
        if d.plan(source(0x9000_0000), Some(&(30..40)), B, 0) != (0..100)
            || d.plan(s, None, B, 0) != (0..100)
            || d.plan(s, Some(&(30..40)), B, 1) != (0..100)
        {
            return TestResult::Fail("unrelated buffer took a partial copy");
        }
        d.presented(s, Some(&(30..40)), Some(B), 0);
        if d.plan(s, Some(&(95..400)), A, 0) != (30..100) {
            return TestResult::Fail("damage not clamped to the frame");
        }
        // A client framebuffer scanned out in place: the staged buffers
        // keep their contents but lose the frames shown meanwhile.
        d.presented(None, None, None, 0);
        if d.plan(s, Some(&(1..2)), A, 0) != (0..100) {
            return TestResult::Fail("buffer kept across a GEM frame");
        }
        // Three buffers (a triple-buffered or externally flipped plane).
        d.presented(s, None, Some(A), 0);
        d.presented(s, Some(&(5..6)), Some(B), 0);
        d.presented(s, Some(&(7..8)), Some(C), 0);
        if d.plan(s, Some(&(9..10)), A, 0) != (5..10)
            || d.plan(s, Some(&(9..10)), B, 0) != (7..10)
            || d.plan(s, Some(&(9..10)), C, 0) != (9..10)
        {
            return TestResult::Fail("per-buffer staleness");
        }
        // A new epoch forgets everything, as does forget.
        d.presented(s, Some(&(1..2)), Some(A), 2);
        if d.plan(s, Some(&(1..2)), B, 2) != (0..100) || d.plan(s, Some(&(1..2)), A, 2) != (1..2) {
            return TestResult::Fail("epoch change kept buffers");
        }
        d.forget();
        if d.plan(s, Some(&(1..2)), A, 2) != (0..100) {
            return TestResult::Fail("forgotten buffers took a partial copy");
        }
        if d.plan(None, Some(&(1..2)), A, 2) != (0..0) {
            return TestResult::Fail("sourceless frame planned rows");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/present-damage",
        damage_copies_only_what_each_buffer_lacks
    );

    fn replaced_frame_keeps_its_damage() -> TestResult {
        let (s, t) = (source(0x8000_0000), source(0x9000_0000));
        if coalesce((s, Some(&(10..20))), (s, Some(&(50..60)))) != Some(10..60)
            || coalesce((s, None), (s, Some(&(50..60)))).is_some()
            || coalesce((t, Some(&(1..2))), (s, Some(&(50..60)))).is_some()
            || coalesce((None, None), (s, Some(&(50..60)))).is_some()
        {
            return TestResult::Fail("coalesced damage");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/present-damage",
        replaced_frame_keeps_its_damage
    );
}
