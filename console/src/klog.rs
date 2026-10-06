//! Kernel log store — the record-based printk buffer behind `/dev/kmsg`,
//! `syslog(2)` and `dmesg`.
//!
//! Model (`kernel/printk/printk.c` + `printk_ringbuffer.c`)
//! --------------------------------------------------------
//! The log is a sequence of RECORDS, not a byte stream. Each record carries
//! a 64-bit sequence number, a monotonic timestamp (ns), a syslog facility
//! and level, `LOG_*` flags and up to [`RECORD_TEXT_MAX`] bytes of text.
//! Readers address the log by sequence number; when the writer laps a slow
//! reader, the reader learns exactly how many records it lost (the gap in
//! sequence numbers) instead of silently reading torn bytes.
//!
//! Storage mirrors Linux's two rings:
//!
//! * a TEXT ring of `log_buf_len` bytes (`__LOG_BUF_LEN`,
//!   `1 << CONFIG_LOG_BUF_SHIFT`; the default here is shift 17 = 128 KiB,
//!   Linux's Kconfig default and Arch's distro setting), in which each
//!   record's text is stored contiguously at a logical position (`lpos`) —
//!   a record that would straddle the end of the buffer is moved to its
//!   start, exactly as `data_alloc` does;
//! * a DESCRIPTOR ring of `log_buf_len >> PRB_AVGBITS` slots (Linux sizes
//!   it for an average record of 32 bytes), indexed by `seq % count`.
//!
//! Writing a record evicts the oldest ones until both its text and its
//! descriptor fit. The default buffers are static (`.bss`), so the log works
//! from the first `write_str` of boot, before any allocator exists.
//! `log_buf_len=` on the kernel command line asks for a bigger buffer; it is
//! parsed by [`log_buf_len_setup`] and honoured by [`setup_log_buf`] once the
//! heap is live, which allocates the new rings and migrates every record
//! (sequence numbers preserved) — Linux's `setup_log_buf`.
//!
//! Lines and continuations
//! -----------------------
//! Kernel `write_str` calls arrive in fragments (`write!` splits a format
//! string into many `write_str`s). Fragments accumulate in a continuation
//! buffer and become ONE record when the `\n` arrives, the way `pr_cont`
//! extends the last record. A pending fragment is not visible to readers
//! until it is terminated (Linux readers likewise only see finalized
//! records). When the continuation buffer fills, or another writer (a
//! `/dev/kmsg` injection) lands a record in between, the fragment so far is
//! committed and the rest of the line becomes a new record flagged
//! `LOG_CONT` (`c` in `/dev/kmsg` output).
//!
//! Concurrency
//! -----------
//! One `IrqSafeSpinLock` guards the whole store. No allocation, formatting
//! that can allocate, or console output happens under it, so the allocator
//! or a console write can never recurse into it. A per-CPU re-entrancy
//! guard ([`IN_RECORD`]) still short-circuits a record attempted from an NMI
//! or fault on the CPU that already holds the lock. The trap and panic sinks
//! in `lib.rs` never touch the store at all.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// `CONFIG_LOG_BUF_SHIFT` — Linux's Kconfig default (`init/Kconfig`), which
/// is also what Arch Linux and most distribution kernels ship.
pub const LOG_BUF_SHIFT: u32 = 17;

/// `__LOG_BUF_LEN` — the static (boot) text buffer size, and the floor for
/// `log_buf_len=`.
pub const DEFAULT_LOG_BUF_LEN: usize = 1 << LOG_BUF_SHIFT;

/// `LOG_BUF_LEN_MAX` — `log_buf_len=` is clamped to 2 GiB.
pub const LOG_BUF_LEN_MAX: u64 = 1 << 31;

/// `PRB_AVGBITS` — the descriptor ring is sized for 32-byte records.
const PRB_AVGBITS: u32 = 5;

const DEFAULT_DESC_COUNT: usize = DEFAULT_LOG_BUF_LEN >> PRB_AVGBITS;

/// `PRINTKRB_RECORD_MAX` — the largest record `vprintk_store` reserves,
/// including the terminating NUL, so a record holds at most
/// `PRINTKRB_RECORD_MAX - 1` bytes of text. `/dev/kmsg` writes longer than
/// this are rejected with `EINVAL`.
pub const PRINTKRB_RECORD_MAX: usize = 1024;

/// Bytes of text a single record can hold.
pub const RECORD_TEXT_MAX: usize = PRINTKRB_RECORD_MAX - 1;

/// `PRINTK_MESSAGE_MAX` — the formatting buffer a record is rendered into
/// for `/dev/kmsg` and `syslog(2)`; output beyond it is truncated.
pub const PRINTK_MESSAGE_MAX: usize = 2048;

/// `enum printk_info_flags::LOG_NEWLINE`.
pub const LOG_NEWLINE: u8 = 2;
/// `enum printk_info_flags::LOG_CONT` — the record is a fragment of a line.
pub const LOG_CONT: u8 = 8;

/// Syslog facility of kernel-generated records (`LOG_KERN`).
pub const LOG_KERN: u8 = 0;
/// Syslog facility forced on `/dev/kmsg` injections without one (`LOG_USER`).
pub const LOG_USER: u8 = 1;

/// One record's metadata (`struct printk_info` + its text block position).
#[derive(Copy, Clone, Debug, Default)]
struct Desc {
    seq: u64,
    /// Logical position of the record's text in the text ring.
    begin: u64,
    ts_nsec: u64,
    len: u16,
    level: u8,
    facility: u8,
    flags: u8,
}

const EMPTY_DESC: Desc = Desc {
    seq: 0,
    begin: 0,
    ts_nsec: 0,
    len: 0,
    level: 0,
    facility: 0,
    flags: 0,
};

/// The pending, unterminated kernel line.
struct Cont {
    buf: [u8; RECORD_TEXT_MAX],
    len: usize,
    active: bool,
    level: u8,
    ts_nsec: u64,
    /// `LOG_CONT` when this line's beginning was already committed as an
    /// earlier record.
    flags: u8,
    /// CPU whose line this is — Linux's `caller_id` check in
    /// `prb_reserve_in_last`: a fragment from another CPU never extends it.
    owner: usize,
}

/// Outcome of a `/dev/kmsg` record read.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KmsgRead {
    /// One record of this many bytes was copied out.
    Record(usize),
    /// No record at or after the cursor — `EAGAIN` / block.
    Empty,
    /// The cursor's record was overwritten; the cursor now names the oldest
    /// surviving record — `EPIPE`.
    Dropped,
    /// The record did not fit the caller's buffer; it is skipped — `EINVAL`.
    TooSmall,
}

/// The rings `Store::grow` replaced, handed back to be freed outside the
/// store lock.
type ReplacedRings = (Option<Box<[u8]>>, Option<Box<[Desc]>>);

struct Store {
    text_static: [u8; DEFAULT_LOG_BUF_LEN],
    descs_static: [Desc; DEFAULT_DESC_COUNT],
    /// Replacement rings installed by `setup_log_buf`.
    text_dyn: Option<Box<[u8]>>,
    descs_dyn: Option<Box<[Desc]>>,
    /// Logical position one past the newest record's text.
    head_lpos: u64,
    /// Oldest record still stored.
    first_seq: u64,
    /// Sequence number the next record gets (`prb_next_seq`).
    next_seq: u64,
    /// `clear_seq` — set by `SYSLOG_ACTION_CLEAR`.
    clear_seq: u64,
    /// `syslog_seq` / `syslog_partial` — `SYSLOG_ACTION_READ`'s cursor.
    syslog_seq: u64,
    syslog_partial: usize,
    cont: Cont,
    /// CPUs (bit `cpu % 64`) whose last line was cut short; their next
    /// record is a `LOG_CONT` fragment.
    cont_broken: u64,
}

impl Store {
    const fn new() -> Self {
        Self {
            text_static: [0; DEFAULT_LOG_BUF_LEN],
            descs_static: [EMPTY_DESC; DEFAULT_DESC_COUNT],
            text_dyn: None,
            descs_dyn: None,
            head_lpos: 0,
            first_seq: 0,
            next_seq: 0,
            clear_seq: 0,
            syslog_seq: 0,
            syslog_partial: 0,
            cont: Cont {
                buf: [0; RECORD_TEXT_MAX],
                len: 0,
                active: false,
                level: 0,
                ts_nsec: 0,
                flags: 0,
                owner: 0,
            },
            cont_broken: 0,
        }
    }

    /// Heap-allocate an empty store without building it on the stack (it is
    /// ~260 KiB). All-zero is a valid empty store: zero sequence numbers,
    /// `None` rings (null niche), inactive continuation.
    fn boxed() -> Box<Self> {
        let layout = core::alloc::Layout::new::<Self>();
        // SAFETY: `Store` is not zero-sized; an all-zero `Store` is a valid
        // value (integers, arrays of integers, `Option<Box<_>>` = None via
        // the null niche, `bool` false), and the pointer comes from the
        // global allocator with `Store`'s layout, as `Box::from_raw` needs.
        unsafe {
            let p = alloc::alloc::alloc_zeroed(layout) as *mut Self;
            if p.is_null() {
                alloc::alloc::handle_alloc_error(layout);
            }
            Box::from_raw(p)
        }
    }

    fn text(&self) -> &[u8] {
        match self.text_dyn.as_deref() {
            Some(t) => t,
            None => &self.text_static,
        }
    }

    fn descs(&self) -> &[Desc] {
        match self.descs_dyn.as_deref() {
            Some(d) => d,
            None => &self.descs_static,
        }
    }

    fn parts(&mut self) -> (&mut [u8], &mut [Desc]) {
        let text: &mut [u8] = match self.text_dyn.as_deref_mut() {
            Some(t) => t,
            None => &mut self.text_static,
        };
        let descs: &mut [Desc] = match self.descs_dyn.as_deref_mut() {
            Some(d) => d,
            None => &mut self.descs_static,
        };
        (text, descs)
    }

    fn desc(&self, seq: u64) -> Desc {
        let d = self.descs();
        d[(seq % d.len() as u64) as usize]
    }

    fn rec_text(&self, d: &Desc) -> &[u8] {
        let t = self.text();
        let p = (d.begin % t.len() as u64) as usize;
        &t[p..p + d.len as usize]
    }

    /// Append a finished record, evicting the oldest ones to make room.
    fn commit(&mut self, facility: u8, level: u8, flags: u8, ts_nsec: u64, text: &[u8]) {
        let text = &text[..text.len().min(RECORD_TEXT_MAX)];
        let size = self.text().len() as u64;
        let ndesc = self.descs().len() as u64;
        let len = text.len() as u64;
        let mut begin = self.head_lpos;
        let off = begin % size;
        if off + len > size {
            // `data_alloc`: a block never wraps; skip to the buffer start.
            begin += size - off;
        }
        let end = begin + len;
        while self.next_seq - self.first_seq >= ndesc {
            self.first_seq += 1;
        }
        while self.first_seq < self.next_seq {
            // The oldest record survives only if no byte of it lies in the
            // physical range the new text is about to overwrite.
            if self.desc(self.first_seq).begin + size >= end {
                break;
            }
            self.first_seq += 1;
        }
        let seq = self.next_seq;
        let (tb, db) = self.parts();
        let p = (begin % size) as usize;
        tb[p..p + text.len()].copy_from_slice(text);
        db[(seq % ndesc) as usize] = Desc {
            seq,
            begin,
            ts_nsec,
            len: text.len() as u16,
            level: level & 7,
            facility,
            flags,
        };
        self.head_lpos = end;
        self.next_seq = seq + 1;
    }

    /// Commit the pending line. `newline == false` means the line was cut
    /// short (record full, or another writer intervened): its owner's next
    /// fragment then starts a record flagged `LOG_CONT`.
    fn flush_cont(&mut self, newline: bool) {
        if !self.cont.active {
            return;
        }
        let (level, flags, ts, len) = (
            self.cont.level,
            self.cont.flags | if newline { LOG_NEWLINE } else { 0 },
            self.cont.ts_nsec,
            self.cont.len,
        );
        // Copy out first: `commit` borrows the store mutably.
        let mut tmp = [0u8; RECORD_TEXT_MAX];
        tmp[..len].copy_from_slice(&self.cont.buf[..len]);
        self.commit(LOG_KERN, level, flags, ts, &tmp[..len]);
        self.cont.active = false;
        self.cont.len = 0;
        if !newline {
            self.cont_broken |= cpu_bit(self.cont.owner);
        }
    }

    /// Kernel `write_str` path: fragments accumulate until `\n`. `cpu` is
    /// the writer's CPU: a fragment never extends another CPU's line.
    fn append(&mut self, level: u8, ts_nsec: u64, cpu: usize, s: &[u8]) {
        if self.cont.active && self.cont.owner != cpu {
            self.flush_cont(false);
        }
        let mut rest = s;
        while !rest.is_empty() {
            if !self.cont.active {
                let bit = cpu_bit(cpu);
                self.cont.active = true;
                self.cont.len = 0;
                self.cont.level = level & 7;
                self.cont.ts_nsec = ts_nsec;
                self.cont.owner = cpu;
                self.cont.flags = if self.cont_broken & bit != 0 {
                    LOG_CONT
                } else {
                    0
                };
                self.cont_broken &= !bit;
            }
            let nl = rest.iter().position(|&b| b == b'\n');
            let seg_end = nl.unwrap_or(rest.len());
            let room = RECORD_TEXT_MAX - self.cont.len;
            let take = seg_end.min(room);
            let at = self.cont.len;
            self.cont.buf[at..at + take].copy_from_slice(&rest[..take]);
            self.cont.len += take;
            if take < seg_end {
                // Record full mid-line: commit, continue in a new record.
                self.flush_cont(false);
                rest = &rest[take..];
                continue;
            }
            match nl {
                Some(i) => {
                    self.flush_cont(true);
                    rest = &rest[i + 1..];
                }
                None => rest = &[],
            }
        }
    }

    /// A whole message from another source (`/dev/kmsg`). A pending kernel
    /// fragment is committed first so sequence order follows arrival order.
    fn emit(&mut self, facility: u8, level: u8, ts_nsec: u64, text: &[u8]) {
        self.flush_cont(false);
        let (text, flags) = match text.split_last() {
            // `printk_sprint`: mark and strip ONE trailing newline.
            Some((b'\n', head)) => (head, LOG_NEWLINE),
            _ => (text, 0),
        };
        self.commit(facility, level, flags, ts_nsec, text);
    }

    /// `prb_read_valid`: the first stored record at or after `seq`.
    fn read_valid(&self, seq: u64) -> Option<(u64, Desc)> {
        let s = seq.max(self.first_seq);
        if s >= self.next_seq {
            return None;
        }
        Some((s, self.desc(s)))
    }

    // ── /dev/kmsg ────────────────────────────────────────────────────

    fn kmsg_read(&self, cursor: &mut u64, out: &mut [u8]) -> KmsgRead {
        let Some((seq, d)) = self.read_valid(*cursor) else {
            return KmsgRead::Empty;
        };
        if seq != *cursor {
            // `pmsg.dropped`: report and resync to the oldest record.
            *cursor = seq;
            return KmsgRead::Dropped;
        }
        // Linux advances BEFORE the size check: a record that does not fit
        // is skipped, and the caller gets EINVAL.
        *cursor = seq + 1;
        let mut w = Bounded::new(PRINTK_MESSAGE_MAX);
        format_ext(&d, self.rec_text(&d), &mut w);
        if w.len > out.len() {
            return KmsgRead::TooSmall;
        }
        out[..w.len].copy_from_slice(&w.buf[..w.len]);
        KmsgRead::Record(w.len)
    }

    // ── syslog(2) ────────────────────────────────────────────────────

    /// `SYSLOG_ACTION_READ` — `syslog_print`.
    fn syslog_read(&mut self, out: &mut [u8]) -> usize {
        let mut len = 0usize;
        let mut size = out.len();
        while size > 0 {
            let Some((seq, d)) = self.read_valid(self.syslog_seq) else {
                break;
            };
            if seq != self.syslog_seq {
                // "message is gone, move to next valid one"
                self.syslog_seq = seq;
                self.syslog_partial = 0;
            }
            let mut w = Bounded::new(PRINTK_MESSAGE_MAX);
            record_print_text(&d, self.rec_text(&d), &mut w);
            let n_full = w.len;
            let skip = self.syslog_partial;
            let n = if n_full - skip <= size {
                self.syslog_seq = seq + 1;
                self.syslog_partial = 0;
                n_full - skip
            } else if len == 0 {
                self.syslog_partial += size;
                size
            } else {
                0
            };
            if n == 0 {
                break;
            }
            out[len..len + n].copy_from_slice(&w.buf[skip..skip + n]);
            len += n;
            size -= n;
        }
        len
    }

    /// `SYSLOG_ACTION_READ_ALL` / `READ_CLEAR` — `syslog_print_all`.
    fn syslog_read_all(&mut self, out: &mut [u8], clear: bool) -> usize {
        let size = out.len();
        // `find_first_fitting_seq(clear_seq, -1, size, true, time)`.
        let start = self.clear_seq.max(self.first_seq);
        let mut total: usize = (start..self.next_seq)
            .map(|s| text_size(&self.desc(s), self.rec_text(&self.desc(s))))
            .sum();
        let mut seq = start;
        while total > size && seq < self.next_seq {
            let d = self.desc(seq);
            total -= text_size(&d, self.rec_text(&d));
            seq += 1;
        }
        let mut len = 0usize;
        while let Some((s, d)) = self.read_valid(seq) {
            let mut w = Bounded::new(PRINTK_MESSAGE_MAX);
            record_print_text(&d, self.rec_text(&d), &mut w);
            if len + w.len > size {
                break;
            }
            out[len..len + w.len].copy_from_slice(&w.buf[..w.len]);
            len += w.len;
            seq = s + 1;
        }
        if clear {
            self.clear_seq = seq;
        }
        len
    }

    /// `SYSLOG_ACTION_SIZE_UNREAD` (from a reader, not `/proc/kmsg`).
    fn syslog_size_unread(&mut self) -> usize {
        let Some((seq, _)) = self.read_valid(self.syslog_seq) else {
            return 0;
        };
        if seq != self.syslog_seq {
            self.syslog_seq = seq;
            self.syslog_partial = 0;
        }
        let sum: usize = (seq..self.next_seq)
            .map(|s| text_size(&self.desc(s), self.rec_text(&self.desc(s))))
            .sum();
        sum - self.syslog_partial
    }

    /// Total `syslog(2)` text size from `clear_seq` on — sizes a buffer.
    fn syslog_all_size(&self) -> usize {
        let start = self.clear_seq.max(self.first_seq);
        (start..self.next_seq)
            .map(|s| text_size(&self.desc(s), self.rec_text(&self.desc(s))))
            .sum()
    }

    /// Install larger rings and move every record into them, keeping their
    /// sequence numbers. Returns the replaced rings for the caller to drop
    /// outside the lock.
    fn grow(&mut self, mut text: Box<[u8]>, mut descs: Box<[Desc]>) -> ReplacedRings {
        let size = text.len() as u64;
        let ndesc = descs.len() as u64;
        let mut lpos = 0u64;
        let mut first = self.first_seq;
        // Keep the newest records that fit (all of them when growing).
        while self.next_seq - first > ndesc {
            first += 1;
        }
        for seq in first..self.next_seq {
            let d = self.desc(seq);
            let t = self.rec_text(&d);
            let len = t.len() as u64;
            if lpos % size + len > size {
                lpos += size - lpos % size;
            }
            let p = (lpos % size) as usize;
            text[p..p + t.len()].copy_from_slice(t);
            descs[(seq % ndesc) as usize] = Desc { begin: lpos, ..d };
            lpos += len;
        }
        self.first_seq = first;
        self.head_lpos = lpos;
        (self.text_dyn.replace(text), self.descs_dyn.replace(descs))
    }

    fn reset(&mut self) {
        self.head_lpos = 0;
        self.first_seq = 0;
        self.next_seq = 0;
        self.clear_seq = 0;
        self.syslog_seq = 0;
        self.syslog_partial = 0;
        self.cont.active = false;
        self.cont.len = 0;
        self.cont.flags = 0;
        self.cont_broken = 0;
    }
}

fn cpu_bit(cpu: usize) -> u64 {
    1u64 << (cpu % 64)
}

// ── formatting ──────────────────────────────────────────────────────

/// Fixed-size output buffer with Linux's truncation semantics.
struct Bounded {
    buf: [u8; PRINTK_MESSAGE_MAX],
    cap: usize,
    len: usize,
}

impl Bounded {
    fn new(cap: usize) -> Self {
        Self {
            buf: [0; PRINTK_MESSAGE_MAX],
            cap: cap.min(PRINTK_MESSAGE_MAX),
            len: 0,
        }
    }

    /// `append_char`: store if there is room.
    fn ch(&mut self, c: u8) {
        if self.len < self.cap {
            self.buf[self.len] = c;
            self.len += 1;
        }
    }

    /// `scnprintf(p, e - p, ...)`: at most `room - 1` bytes (one is kept for
    /// the NUL a C string needs).
    fn snp(&mut self, s: &[u8]) {
        let room = self.cap - self.len;
        let n = s.len().min(room.saturating_sub(1));
        self.buf[self.len..self.len + n].copy_from_slice(&s[..n]);
        self.len += n;
    }

    fn put(&mut self, s: &[u8]) {
        for &c in s {
            self.ch(c);
        }
    }
}

/// Decimal formatting into a small stack buffer, right-aligned to `width`
/// with `pad`.
fn fmt_u64(mut v: u64, width: usize, pad: u8, out: &mut [u8; 24]) -> usize {
    let mut tmp = [0u8; 20];
    let mut n = 0;
    loop {
        tmp[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let mut len = 0;
    while len + n < width {
        out[len] = pad;
        len += 1;
    }
    for i in (0..n).rev() {
        out[len] = tmp[i];
        len += 1;
    }
    len
}

/// `info_print_ext_header` + `msg_print_ext_body` — one `/dev/kmsg` record:
/// `"<prio>,<seq>,<ts_usec>,<flags>;<escaped text>\n"`.
fn format_ext(d: &Desc, text: &[u8], w: &mut Bounded) {
    let mut hdr = [0u8; 80];
    let mut h = 0;
    let mut num = [0u8; 24];
    let prio = ((d.facility as u64) << 3) | d.level as u64;
    for v in [prio, d.seq, d.ts_nsec / 1000] {
        let n = fmt_u64(v, 0, b' ', &mut num);
        hdr[h..h + n].copy_from_slice(&num[..n]);
        h += n;
        hdr[h] = b',';
        h += 1;
    }
    hdr[h] = if d.flags & LOG_CONT != 0 { b'c' } else { b'-' };
    h += 1;
    hdr[h] = b';';
    h += 1;
    w.snp(&hdr[..h]);
    // `msg_add_ext_text`: escape non-printables and '\'.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &c in text {
        if !(b' '..127).contains(&c) || c == b'\\' {
            w.snp(&[b'\\', b'x', HEX[(c >> 4) as usize], HEX[(c & 15) as usize]]);
        } else {
            w.ch(c);
        }
    }
    w.ch(b'\n');
}

/// `info_print_prefix(info, syslog=true, time=true)`:
/// `"<prio>[%5lu.%06lu] "`.
fn syslog_prefix(d: &Desc, out: &mut [u8; 48]) -> usize {
    let mut num = [0u8; 24];
    let mut p = 0;
    let mut put = |s: &[u8], p: &mut usize| {
        out[*p..*p + s.len()].copy_from_slice(s);
        *p += s.len();
    };
    put(b"<", &mut p);
    let n = fmt_u64(
        ((d.facility as u64) << 3) | d.level as u64,
        0,
        b' ',
        &mut num,
    );
    put(&num[..n], &mut p);
    put(b">[", &mut p);
    let n = fmt_u64(d.ts_nsec / 1_000_000_000, 5, b' ', &mut num);
    put(&num[..n], &mut p);
    put(b".", &mut p);
    let n = fmt_u64((d.ts_nsec % 1_000_000_000) / 1000, 6, b'0', &mut num);
    put(&num[..n], &mut p);
    put(b"] ", &mut p);
    p
}

/// `get_record_print_text_size` — the size `record_print_text` would
/// produce, before buffer truncation.
fn text_size(d: &Desc, text: &[u8]) -> usize {
    let mut pfx = [0u8; 48];
    let prefix_len = syslog_prefix(d, &mut pfx);
    let lines = 1 + text.iter().filter(|&&b| b == b'\n').count();
    prefix_len * lines + text.len() + 1
}

/// `record_print_text(r, syslog=true, time=true)`: every line of the record
/// prefixed, a trailing newline added, lines that would not fit the
/// `PRINTK_MESSAGE_MAX` buffer (with its terminator) dropped.
fn record_print_text(d: &Desc, text: &[u8], w: &mut Bounded) {
    let mut pfx = [0u8; 48];
    let prefix_len = syslog_prefix(d, &mut pfx);
    for line in text.split(|&b| b == b'\n') {
        if w.len + prefix_len + line.len() + 1 + 1 > w.cap {
            break;
        }
        w.put(&pfx[..prefix_len]);
        w.put(line);
        w.put(b"\n");
    }
}

// ── global store ────────────────────────────────────────────────────

static RING: IrqSafeSpinLock<Store> = IrqSafeSpinLock::new(Store::new());

/// Re-entrancy guard: the CPU currently inside the store's critical section
/// (`usize::MAX` when none). A `record` from an NMI or fault on THAT CPU
/// would spin forever on the lock it interrupted, so it is dropped instead.
/// Other CPUs simply wait for the lock — their messages are not lost.
static IN_RECORD: AtomicUsize = AtomicUsize::new(usize::MAX);

fn with_store<R>(f: impl FnOnce(&mut Store) -> R) -> Option<R> {
    let cpu = narf_lib::percpu::current_cpu();
    if IN_RECORD.load(Ordering::Acquire) == cpu {
        return None;
    }
    let mut g = RING.lock();
    IN_RECORD.store(cpu, Ordering::Release);
    let r = f(&mut g);
    IN_RECORD.store(usize::MAX, Ordering::Release);
    drop(g);
    Some(r)
}

/// Monotonic clock for record timestamps (ns), installed once the kernel's
/// clocksource is calibrated. Until then records are stamped 0 — Linux's
/// early-boot `[    0.000000]` before `sched_clock` runs.
static CLOCK: AtomicUsize = AtomicUsize::new(0);

/// Install the timestamp source. It must be callable from any context
/// (IRQ, with locks held) and must not log.
pub fn set_clock(f: fn() -> u64) {
    CLOCK.store(f as usize, Ordering::Release);
}

fn now_ns() -> u64 {
    let f = CLOCK.load(Ordering::Acquire);
    if f == 0 {
        return 0;
    }
    // SAFETY: only `set_clock` stores here, from a `fn() -> u64`.
    let f: fn() -> u64 = unsafe { core::mem::transmute(f) };
    f()
}

/// Record kernel console text at `DEFAULT_MESSAGE_LOGLEVEL`.
pub fn record(s: &str) {
    record_level(DEFAULT_MESSAGE_LOGLEVEL, s);
}

/// Record kernel console text at `level`. Text is split into records at
/// `\n`; an unterminated fragment waits for the rest of its line.
pub fn record_level(level: u32, s: &str) {
    if s.is_empty() {
        return;
    }
    let ts = now_ns();
    let cpu = narf_lib::percpu::current_cpu();
    let _ = with_store(|st| st.append(level.min(7) as u8, ts, cpu, s.as_bytes()));
}

/// Store one complete message from userspace (`/dev/kmsg` write) with an
/// explicit facility and level. One trailing newline is stripped; the text
/// is truncated to [`RECORD_TEXT_MAX`].
pub fn emit(facility: u8, level: u8, text: &[u8]) {
    let ts = now_ns();
    let _ = with_store(|st| st.emit(facility, level, ts, text));
}

/// `prb_first_valid_seq` — the oldest stored record.
pub fn first_seq() -> u64 {
    with_store(|s| s.first_seq).unwrap_or(0)
}

/// `prb_next_seq` — one past the newest record.
pub fn next_seq() -> u64 {
    with_store(|s| s.next_seq).unwrap_or(0)
}

/// `clear_seq` — where the last `SYSLOG_ACTION_CLEAR` left `READ_ALL`.
pub fn clear_seq() -> u64 {
    with_store(|s| s.clear_seq).unwrap_or(0)
}

/// `log_buf_len` — the text buffer size (`SYSLOG_ACTION_SIZE_BUFFER`).
pub fn log_buf_len() -> usize {
    with_store(|s| s.text().len()).unwrap_or(DEFAULT_LOG_BUF_LEN)
}

/// `devkmsg_read`'s record step: render the record at `*cursor` into `out`.
pub fn kmsg_read(cursor: &mut u64, out: &mut [u8]) -> KmsgRead {
    with_store(|s| s.kmsg_read(cursor, out)).unwrap_or(KmsgRead::Empty)
}

/// `devkmsg_poll`: `None` when no record is at or after `cursor`;
/// `Some(vanished)` otherwise, `vanished` meaning the cursor's own record
/// was overwritten (Linux adds `EPOLLERR | EPOLLPRI`).
pub fn kmsg_poll(cursor: u64) -> Option<bool> {
    with_store(|s| s.read_valid(cursor).map(|(seq, _)| seq != cursor)).flatten()
}

/// `SYSLOG_ACTION_READ` into a kernel buffer; returns bytes produced.
pub fn syslog_read(out: &mut [u8]) -> usize {
    with_store(|s| s.syslog_read(out)).unwrap_or(0)
}

/// `SYSLOG_ACTION_READ_ALL` (`clear == false`) / `READ_CLEAR`.
pub fn syslog_read_all(out: &mut [u8], clear: bool) -> usize {
    with_store(|s| s.syslog_read_all(out, clear)).unwrap_or(0)
}

/// Bytes `syslog_read_all` would produce with an unlimited buffer — lets a
/// caller size its buffer before taking the store lock.
pub fn syslog_all_size() -> usize {
    with_store(|s| s.syslog_all_size()).unwrap_or(0)
}

/// `SYSLOG_ACTION_SIZE_UNREAD`.
pub fn syslog_size_unread() -> usize {
    with_store(|s| s.syslog_size_unread()).unwrap_or(0)
}

/// `syslog_clear()` — `clear_seq = prb_next_seq()`.
pub fn syslog_clear() {
    let _ = with_store(|s| s.clear_seq = s.next_seq);
}

/// Test/boot hook: reset the `SYSLOG_ACTION_READ` and `CLEAR` cursors.
#[doc(hidden)]
pub fn __reset_syslog_cursors() {
    let _ = with_store(|s| {
        s.syslog_seq = 0;
        s.syslog_partial = 0;
        s.clear_seq = 0;
    });
}

/// The text of every stored record from `seq` on, each followed by `\n`
/// (no prefixes). Diagnostic/test helper; allocates outside the lock.
pub fn text_since(seq: u64) -> Vec<u8> {
    for _ in 0..4 {
        let need = with_store(|s| {
            let start = seq.max(s.first_seq);
            (start..s.next_seq)
                .map(|q| s.desc(q).len as usize + 1)
                .sum::<usize>()
        })
        .unwrap_or(0);
        let mut out = alloc::vec![0u8; need];
        let got = with_store(|s| {
            let start = seq.max(s.first_seq);
            let mut n = 0;
            for q in start..s.next_seq {
                let d = s.desc(q);
                let t = s.rec_text(&d);
                if n + t.len() + 1 > out.len() {
                    return None;
                }
                out[n..n + t.len()].copy_from_slice(t);
                out[n + t.len()] = b'\n';
                n += t.len() + 1;
            }
            Some(n)
        })
        .flatten();
        if let Some(n) = got {
            out.truncate(n);
            return out;
        }
    }
    Vec::new()
}

/// All stored record text (see [`text_since`]).
pub fn snapshot() -> Vec<u8> {
    text_since(0)
}

/// Test-only: empty the store and every cursor.
#[doc(hidden)]
pub fn __reset_for_test() {
    let _ = with_store(|s| s.reset());
}

// ── log_buf_len= ────────────────────────────────────────────────────

/// `new_log_buf_len` — set by `log_buf_len=`, consumed by `setup_log_buf`.
static NEW_LOG_BUF_LEN: AtomicU64 = AtomicU64::new(0);

/// `memparse`: `simple_strtoull(s, &end, 0)` then an optional
/// K/M/G/T/P/E suffix (each a further `<< 10`). Returns 0 when no number
/// is present, like Linux.
pub fn memparse(s: &str) -> u64 {
    let b = s.as_bytes();
    // `_parse_integer_fixup_radix`: "0x" means hex only when a hex digit
    // follows; any other leading '0' means octal.
    let (radix, mut i) =
        if b.len() >= 3 && b[0] == b'0' && (b[1] | 0x20) == b'x' && b[2].is_ascii_hexdigit() {
            (16u64, 2)
        } else if b.first() == Some(&b'0') {
            (8, 1)
        } else {
            (10, 0)
        };
    let mut v: u64 = 0;
    let start = i;
    while i < b.len() {
        let d = match b[i] {
            c @ b'0'..=b'9' => (c - b'0') as u64,
            c @ b'a'..=b'f' => (c - b'a' + 10) as u64,
            c @ b'A'..=b'F' => (c - b'A' + 10) as u64,
            _ => break,
        };
        if d >= radix {
            break;
        }
        v = v.wrapping_mul(radix).wrapping_add(d);
        i += 1;
    }
    if i == start && radix != 8 {
        return 0;
    }
    let shift = match b.get(i).map(|c| c | 0x20) {
        Some(b'e') => 60,
        Some(b'p') => 50,
        Some(b't') => 40,
        Some(b'g') => 30,
        Some(b'm') => 20,
        Some(b'k') => 10,
        _ => 0,
    };
    v.wrapping_shl(shift)
}

/// `log_buf_len_update`: the text-buffer size `log_buf_len=<arg>` would
/// install, or `None` when it would not grow the buffer. Clamped to
/// [`LOG_BUF_LEN_MAX`], rounded up to a power of two, and only taken when
/// larger than the current `log_buf_len`.
pub fn log_buf_len_value(arg: &str, current: usize) -> Option<usize> {
    let mut size = memparse(arg);
    if size > LOG_BUF_LEN_MAX {
        size = LOG_BUF_LEN_MAX;
    }
    if size != 0 {
        size = size.next_power_of_two();
    }
    (size > current as u64).then_some(size as usize)
}

/// `log_buf_len_setup` — the `log_buf_len=` early parameter.
pub fn log_buf_len_setup(arg: &str) {
    if memparse(arg) > LOG_BUF_LEN_MAX {
        crate::write_str_level(3, "log_buf over 2G is not supported.\n");
    }
    if let Some(size) = log_buf_len_value(arg, log_buf_len()) {
        NEW_LOG_BUF_LEN.store(size as u64, Ordering::Release);
    }
}

fn try_zeroed<T: Copy>(n: usize, zero: T) -> Option<Box<[T]>> {
    let mut v: Vec<T> = Vec::new();
    v.try_reserve_exact(n).ok()?;
    v.resize(n, zero);
    Some(v.into_boxed_slice())
}

/// `setup_log_buf`: once the heap is live, install the buffer
/// `log_buf_len=` asked for and migrate the boot log into it. Allocation
/// happens before the store lock is taken and the replaced rings are freed
/// after it is dropped, so the allocator can never recurse into the store.
pub fn setup_log_buf() {
    use core::fmt::Write as _;
    let size = NEW_LOG_BUF_LEN.swap(0, Ordering::AcqRel) as usize;
    if size == 0 || size <= log_buf_len() {
        return;
    }
    let Some(text) = try_zeroed(size, 0u8) else {
        let _ = writeln!(
            crate::PriorityWriter::<3>,
            "log_buf_len: {size} text bytes not available"
        );
        return;
    };
    let ndesc = size >> PRB_AVGBITS;
    let Some(descs) = try_zeroed(ndesc, EMPTY_DESC) else {
        let _ = writeln!(
            crate::PriorityWriter::<3>,
            "log_buf_len: {} desc bytes not available",
            ndesc * core::mem::size_of::<Desc>()
        );
        return;
    };
    let old = with_store(|s| s.grow(text, descs));
    drop(old);
    let _ = writeln!(crate::Writer, "log_buf_len: {} bytes", log_buf_len());
}

// ── console loglevel ────────────────────────────────────────────────

/// `console_loglevel` — messages at a level NUMERICALLY LOWER than this go
/// to the console (`kernel/printk/printk.c`). `syslog(2)`'s
/// `SYSLOG_ACTION_CONSOLE_{OFF,ON,LEVEL}` read and write it, and
/// `/proc/sys/kernel/printk` reports it as its first field.
///
static CONSOLE_LOGLEVEL: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(7);

/// `minimum_console_loglevel` — `CONSOLE_LEVEL` is clamped up to this, so
/// console output can never be silenced below emergencies.
pub const MINIMUM_CONSOLE_LOGLEVEL: u32 = 1;
/// `default_message_loglevel`.
pub const DEFAULT_MESSAGE_LOGLEVEL: u32 = 4;
/// `default_console_loglevel` — also `CONSOLE_ON`'s restore target when no
/// level was saved.
pub const DEFAULT_CONSOLE_LOGLEVEL: u32 = 7;

pub fn console_loglevel() -> u32 {
    CONSOLE_LOGLEVEL.load(Ordering::Relaxed)
}

pub fn set_console_loglevel(level: u32) {
    CONSOLE_LOGLEVEL.store(level, Ordering::Relaxed);
}

/// Linux printk rule: a message reaches the physical console when its
/// numeric priority is lower than `console_loglevel`. The log store records
/// it regardless, so quiet boots retain complete diagnostics for dmesg.
pub fn console_allows(message_level: u32) -> bool {
    message_level < console_loglevel()
}

mod tests;
