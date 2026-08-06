//! `BPF_MAP_TYPE_RINGBUF` — a single multi-producer / single-consumer stream.
//!
//! A ring buffer is not a keyed map: it has no key, no value width, and none of
//! the element ops. It is a byte stream a BPF program *appends variable-length
//! records to* and a consumer *drains in order*. So it does not implement the
//! keyed [`BpfMapOps`](crate::map::BpfMapOps) surface with real bodies — every
//! one of them returns [`MapError::Invalid`], which is exactly what Linux's
//! `ringbuf_map_*` element ops return (`EINVAL`). It is reached instead through
//! [`RingBuf::output`] (the producer path, which the `bpf_ringbuf_output` kfunc
//! will call) and [`RingBuf::consume_one`] (the consumer path, which a future
//! `mmap` + `poll` surface will replace with a shared-memory protocol).
//!
//! ## The wire protocol
//!
//! Producer and consumer share two monotonically increasing byte offsets,
//! `producer_pos` and `consumer_pos`, into a data area of `data_size` bytes.
//! `data_size` is a power of two, so `pos & (data_size - 1)` is the physical
//! offset and the offsets themselves never need to wrap. Each record is a
//! 64-bit header — a 32-bit length carrying two flag bits in its top, plus a
//! 32-bit page offset that only the `mmap` reverse-mapping needs — followed by
//! the payload padded up to 8 bytes. Record offsets are therefore always
//! 8-aligned and `data_size` is a multiple of 8, so a *header* never straddles
//! the wrap even though a *payload* can.
//!
//! The [`BUSY`] bit marks a record whose payload is still being written; a
//! consumer that reaches one stops, because nothing past it is readable yet.
//! The [`DISCARD`] bit marks a reserved record the producer abandoned; a
//! consumer skips it. [`output`](RingBuf::output) writes a complete record
//! under the lock and never sets `BUSY`; the split reserve/submit path that
//! does is a later stage, and the consumer already honours the bit so that path
//! needs no change here.

use alloc::boxed::Box;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::map::{BpfMapOps, MapAttr, MapError};

/// Bytes of record header: a 32-bit length (with flags) + a 32-bit page offset.
const HDR_LEN: u64 = 8;

/// Set in a record's length word while its payload is still being written.
/// A consumer that reaches a busy record stops — nothing beyond it is ready.
pub const BUSY: u32 = 0x8000_0000;

/// Set in a record's length word when the producer reserved space and then
/// abandoned it. A consumer skips the record and moves on.
pub const DISCARD: u32 = 0x4000_0000;

/// The bits of the length word that are the actual payload length.
const LEN_MASK: u32 = !(BUSY | DISCARD);

/// Round a byte count up to the 8-byte record granularity.
#[inline]
const fn round_up8(n: u64) -> u64 {
    (n + 7) & !7
}

/// Why a record could not be appended.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RingBufError {
    /// The record, header included, is larger than the whole ring — it could
    /// never fit however empty the ring is.
    RecordTooBig,
    /// The ring has too little free space for this record right now. A
    /// transient condition: draining records frees room.
    Full,
}

/// The mutable state, behind the lock.
#[derive(Debug)]
struct State {
    /// `data_size` bytes; indexed by `pos & mask`.
    buf: Box<[u8]>,
    /// Next byte the consumer will read. Only the consumer advances it.
    consumer_pos: u64,
    /// Next byte the producer will write. Only a producer advances it.
    producer_pos: u64,
}

/// A `BPF_MAP_TYPE_RINGBUF`.
#[derive(Debug)]
pub struct RingBuf {
    /// The map shape, so [`BpfMapOps::attr`] can report it. `key_size` and
    /// `value_size` are 0; `max_entries` is `data_size`.
    attr: MapAttr,
    /// The data area size — a power of two.
    data_size: u64,
    /// `data_size - 1`, for masking an offset to a physical index.
    mask: u64,
    state: IrqSafeSpinLock<State>,
}

impl RingBuf {
    /// Create a ring buffer whose data area is `attr.max_entries` bytes.
    ///
    /// The caller ([`crate::map::BpfMap::create`]) has already validated that
    /// `max_entries` is a non-zero power of two and a page multiple, and has
    /// charged the footprint, so this only allocates.
    #[must_use]
    pub fn new(attr: MapAttr) -> Self {
        let data_size = u64::from(attr.max_entries);
        let buf = alloc::vec![0u8; data_size as usize].into_boxed_slice();
        Self {
            attr,
            data_size,
            mask: data_size - 1,
            state: IrqSafeSpinLock::new(State {
                buf,
                consumer_pos: 0,
                producer_pos: 0,
            }),
        }
    }

    /// The data-area size in bytes.
    #[must_use]
    pub fn ring_size(&self) -> u64 {
        self.data_size
    }

    /// Bytes appended but not yet consumed. The `bpf_ringbuf_query`
    /// `BPF_RB_AVAIL_DATA` answer.
    #[must_use]
    pub fn available_data(&self) -> u64 {
        let st = self.state.lock();
        st.producer_pos.wrapping_sub(st.consumer_pos)
    }

    /// The producer position — total bytes ever reserved. `BPF_RB_PROD_POS`.
    #[must_use]
    pub fn producer_pos(&self) -> u64 {
        self.state.lock().producer_pos
    }

    /// The consumer position — total bytes ever drained. `BPF_RB_CONS_POS`.
    #[must_use]
    pub fn consumer_pos(&self) -> u64 {
        self.state.lock().consumer_pos
    }

    /// Append one record carrying `data`, atomically.
    ///
    /// The producer path a `bpf_ringbuf_output` call takes: reserve, copy, and
    /// commit under one lock, so a partially written record is never visible.
    /// The payload is copied *before* `producer_pos` advances, so a consumer
    /// reading `producer_pos` only ever sees fully written records.
    ///
    /// # Errors
    ///
    /// [`RingBufError::RecordTooBig`] if the record cannot fit in an empty ring;
    /// [`RingBufError::Full`] if it cannot fit right now.
    pub fn output(&self, data: &[u8]) -> Result<(), RingBufError> {
        let len = data.len() as u64;
        let need = HDR_LEN + round_up8(len);
        // A payload length must leave the flag bits clear, and the whole record
        // must be able to fit in the ring at all.
        if len > u64::from(LEN_MASK) || need > self.data_size {
            return Err(RingBufError::RecordTooBig);
        }
        let mut st = self.state.lock();
        let used = st.producer_pos.wrapping_sub(st.consumer_pos);
        if need > self.data_size - used {
            return Err(RingBufError::Full);
        }
        let ppos = st.producer_pos;
        // Payload first, then a committed (non-`BUSY`) header, then publish by
        // advancing `producer_pos`.
        copy_in(&mut st.buf, self.mask, ppos + HDR_LEN, data);
        write_header(&mut st.buf, self.mask, ppos, len as u32);
        st.producer_pos = ppos + need;
        Ok(())
    }

    /// Drain the next readable record, or `None` if the ring is caught up or its
    /// head record is still being written.
    ///
    /// Skips abandoned ([`DISCARD`]) records. Allocates the returned `Vec`, so
    /// it is a consumer-side (not program-side) call — the eventual `mmap`
    /// surface reads in place without copying.
    #[must_use]
    pub fn consume_one(&self) -> Option<Vec<u8>> {
        let mut st = self.state.lock();
        loop {
            if st.consumer_pos >= st.producer_pos {
                return None;
            }
            let hpos = st.consumer_pos;
            let hoff = (hpos & self.mask) as usize;
            let len_word = u32::from_le_bytes([
                st.buf[hoff],
                st.buf[hoff + 1],
                st.buf[hoff + 2],
                st.buf[hoff + 3],
            ]);
            // A record still being written blocks everything behind it.
            if len_word & BUSY != 0 {
                return None;
            }
            let len = u64::from(len_word & LEN_MASK);
            let total = HDR_LEN + round_up8(len);
            if len_word & DISCARD != 0 {
                st.consumer_pos = hpos + total;
                continue;
            }
            let out = copy_out(&st.buf, self.mask, hpos + HDR_LEN, len as usize);
            st.consumer_pos = hpos + total;
            return Some(out);
        }
    }
}

/// Write an 8-byte record header at `pos`. `pos` is 8-aligned and the header
/// never straddles the wrap, so this is a plain in-place write.
fn write_header(buf: &mut [u8], mask: u64, pos: u64, len: u32) {
    let off = (pos & mask) as usize;
    buf[off..off + 4].copy_from_slice(&len.to_le_bytes());
    // `pg_off`: only the mmap reverse-mapping consults it. Zero here.
    buf[off + 4..off + 8].copy_from_slice(&0u32.to_le_bytes());
}

/// Copy `src` into the ring at byte offset `start`, wrapping at the end.
fn copy_in(buf: &mut [u8], mask: u64, start: u64, src: &[u8]) {
    let n = buf.len();
    let s = (start & mask) as usize;
    let first = core::cmp::min(src.len(), n - s);
    buf[s..s + first].copy_from_slice(&src[..first]);
    if first < src.len() {
        let rest = src.len() - first;
        buf[..rest].copy_from_slice(&src[first..]);
    }
}

/// Copy `len` bytes out of the ring from byte offset `start`, wrapping.
fn copy_out(buf: &[u8], mask: u64, start: u64, len: usize) -> Vec<u8> {
    let n = buf.len();
    let s = (start & mask) as usize;
    let first = core::cmp::min(len, n - s);
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&buf[s..s + first]);
    if first < len {
        out.extend_from_slice(&buf[..len - first]);
    }
    out
}

/// A ring buffer presents the keyed map surface only to refuse it: `lookup`,
/// `update`, `delete`, and `get_next_key` are all `EINVAL`, exactly as Linux's
/// `ringbuf_map_*` ops are. The stream is reached through [`RingBuf::output`]
/// and [`RingBuf::consume_one`] instead.
impl BpfMapOps for RingBuf {
    fn attr(&self) -> MapAttr {
        self.attr
    }

    fn syscall_value_bytes(&self) -> usize {
        0
    }

    fn lookup(&self, _key: &[u8], _out: &mut [u8]) -> Result<(), MapError> {
        Err(MapError::Invalid)
    }

    fn update(&self, _key: &[u8], _value: &[u8], _flags: u64) -> Result<(), MapError> {
        Err(MapError::Invalid)
    }

    fn delete(&self, _key: &[u8]) -> Result<(), MapError> {
        Err(MapError::Invalid)
    }

    fn next_key(&self, _key: Option<&[u8]>, _out: &mut [u8]) -> Result<(), MapError> {
        Err(MapError::Invalid)
    }

    fn lookup_local(&self, _key: &[u8], _out: &mut [u8]) -> Result<(), MapError> {
        Err(MapError::Invalid)
    }

    fn update_local(&self, _key: &[u8], _value: &[u8], _flags: u64) -> Result<(), MapError> {
        Err(MapError::Invalid)
    }
}
