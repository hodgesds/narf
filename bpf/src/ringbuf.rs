//! `BPF_MAP_TYPE_RINGBUF` — a single multi-producer / single-consumer stream.
//!
//! A ring buffer is not a keyed map: it has no key, no value width, and none of
//! the element ops. It is a byte stream a BPF program *appends variable-length
//! records to* and a consumer *drains in order*. So it does not implement the
//! keyed [`BpfMapOps`](crate::map::BpfMapOps) surface with real bodies — every
//! one of them returns [`MapError::Invalid`], which is exactly what Linux's
//! `ringbuf_map_*` element ops return (`EINVAL`). It is reached instead through
//! [`RingBuf::output`] (the producer path, which the `bpf_ringbuf_output` kfunc
//! calls) and, on the consumer side, either [`RingBuf::consume_one`] (an
//! in-kernel drain, used by tests and any kernel reader) or the shared-memory
//! `mmap` protocol a userspace consumer drives through [`RingBuf::mmap_frames`].
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
//!
//! ## Backing storage
//!
//! The two positions and the data area live in **physical frames**, not on the
//! heap, so the same bytes the kernel producer writes can be `mmap`ed straight
//! into a userspace consumer with no copy. The positions sit at offset zero of
//! two contiguous control pages — page 0 `consumer_pos`, page 1 `producer_pos`
//! — as `AtomicU64`s a userspace mapping shares; the data area is one
//! contiguous block of `data_size` bytes. All three are enumerated by
//! [`RingBuf::mmap_frames`] in the order userspace expects (consumer, producer,
//! data). Publication is a `Release` store to `producer_pos` after the payload
//! is written, and a consumer's `Acquire` load of it is what makes the shared
//! memory safe across the boundary — Linux's
//! `smp_store_release`/`smp_load_acquire` ring-buffer discipline.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_bpf_verifier::kfunc::{ArgDesc, ArgFlags, PtrKind, TypeKey, TypeKind, ValidityDomain};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{alloc_pages_on, free_pages, PhysFrame};

use crate::map::{BpfMapOps, MapAttr, MapError};
use crate::types::BpfType;

/// Bytes in a page — the granularity `mmap` maps at, and the size of each
/// control page. 4 KiB on both supported arches.
const PAGE: u64 = 4096;

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

/// A `BPF_MAP_TYPE_RINGBUF`.
///
/// The positions and the data area are frame-backed (see the module's *Backing
/// storage* note) so a userspace consumer can `mmap` the very bytes the kernel
/// producer writes. `PhysFrame` is a plain physical address, so every field is
/// `Send`/`Sync`; the atomics and the producer lock are what make concurrent
/// access sound.
#[derive(Debug)]
pub struct RingBuf {
    /// The map shape, so [`BpfMapOps::attr`] can report it. `key_size` and
    /// `value_size` are 0; `max_entries` is `data_size`.
    attr: MapAttr,
    /// The data area size — a power of two.
    data_size: u64,
    /// `data_size - 1`, for masking an offset to a physical index.
    mask: u64,
    /// Buddy order of the [`data`](Self::data) block: `log2(data_size / PAGE)`.
    data_order: u8,
    /// Two contiguous control pages. Page 0 holds `consumer_pos`, page 1 holds
    /// `producer_pos`, each an `AtomicU64` at offset zero shared with userspace.
    control: PhysFrame,
    /// The contiguous data area, `data_size` bytes, indexed by `pos & mask`.
    data: PhysFrame,
    /// Serialises producers and guards the data writes plus the `producer_pos`
    /// publish. The consumer is lock-free: it reads `producer_pos` with
    /// `Acquire` and advances only `consumer_pos`.
    producer_lock: IrqSafeSpinLock<()>,
}

impl RingBuf {
    /// Create a ring buffer whose data area is `attr.max_entries` bytes.
    ///
    /// The caller ([`crate::map::BpfMap::create`]) has already validated that
    /// `max_entries` is a non-zero power of two and a page multiple. The frames
    /// are allocated here, and the buddy allocator is the ring's cgroup
    /// accountant — the map layer takes no separate footprint charge for a ring
    /// (see `footprint_bytes`).
    ///
    /// # Errors
    ///
    /// [`MapError::NoMemory`] if either the control pages or the data block
    /// cannot be allocated (including a `memory.max` denial).
    pub fn new(attr: MapAttr) -> Result<Self, MapError> {
        let data_size = u64::from(attr.max_entries);
        // data_size is a page-multiple power of two, so its page count is a
        // power of two and this is its exact buddy order.
        let data_order = (data_size / PAGE).trailing_zeros() as u8;
        // The two control pages are one order-1 (2-page) contiguous block.
        let control = alloc_pages_on(0, 1).map_err(|_| MapError::NoMemory)?;
        let data = match alloc_pages_on(0, data_order) {
            Ok(f) => f,
            Err(_) => {
                free_pages(control, 1);
                return Err(MapError::NoMemory);
            }
        };
        // Positions start at zero and the data area must read clean until
        // written.
        // SAFETY: both blocks are freshly allocated, owned here, and
        // identity-mapped for their full extents (2 pages / `data_size` bytes).
        unsafe {
            core::ptr::write_bytes(
                control.start_address().raw() as *mut u8,
                0,
                (2 * PAGE) as usize,
            );
            core::ptr::write_bytes(data.start_address().raw() as *mut u8, 0, data_size as usize);
        }
        Ok(Self {
            attr,
            data_size,
            mask: data_size - 1,
            data_order,
            control,
            data,
            producer_lock: IrqSafeSpinLock::new(()),
        })
    }

    /// The `consumer_pos` cell, at offset zero of control page 0.
    fn consumer(&self) -> &AtomicU64 {
        // SAFETY: control page 0 is a live identity-mapped frame; offset zero is
        // a naturally aligned `u64` shared with the userspace consumer mapping.
        unsafe { &*(self.control.start_address().raw() as *const AtomicU64) }
    }

    /// The `producer_pos` cell, at offset zero of control page 1.
    fn producer(&self) -> &AtomicU64 {
        // SAFETY: control page 1 is the second frame of the order-1 block;
        // offset zero there is a naturally aligned `u64`.
        unsafe { &*((self.control.start_address().raw() + PAGE) as *const AtomicU64) }
    }

    /// The base of the contiguous data area.
    fn data_ptr(&self) -> *mut u8 {
        self.data.start_address().raw() as *mut u8
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
        let prod = self.producer().load(Ordering::Acquire);
        let cons = self.consumer().load(Ordering::Acquire);
        prod.wrapping_sub(cons)
    }

    /// The producer position — total bytes ever reserved. `BPF_RB_PROD_POS`.
    #[must_use]
    pub fn producer_pos(&self) -> u64 {
        self.producer().load(Ordering::Acquire)
    }

    /// The consumer position — total bytes ever drained. `BPF_RB_CONS_POS`.
    #[must_use]
    pub fn consumer_pos(&self) -> u64 {
        self.consumer().load(Ordering::Acquire)
    }

    /// Whether a record of `len` payload bytes would fit right now.
    ///
    /// The reserve path checks this up front so a reservation that could never
    /// be committed is declined at `bpf_ringbuf_reserve` time — the caller then
    /// null-checks, as the API requires.
    #[must_use]
    pub fn has_room(&self, len: usize) -> bool {
        let need = HDR_LEN + round_up8(len as u64);
        if need > self.data_size {
            return false;
        }
        let _guard = self.producer_lock.lock();
        let used = self
            .producer()
            .load(Ordering::Relaxed)
            .wrapping_sub(self.consumer().load(Ordering::Acquire));
        need <= self.data_size - used
    }

    /// Append one record carrying `data`, atomically.
    ///
    /// The producer path a `bpf_ringbuf_output` call takes: reserve, copy, and
    /// commit under one lock, so a partially written record is never visible.
    /// The payload is copied *before* `producer_pos` advances (a `Release`
    /// store), so a consumer whose `Acquire` load sees the new position also
    /// sees the whole record. On success a readiness `notify` wakes any parked
    /// `poll`/`epoll` consumer promptly.
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
        {
            let _guard = self.producer_lock.lock();
            let ppos = self.producer().load(Ordering::Relaxed);
            let used = ppos.wrapping_sub(self.consumer().load(Ordering::Acquire));
            if need > self.data_size - used {
                return Err(RingBufError::Full);
            }
            let base = self.data_ptr();
            // SAFETY: `base .. base + data_size` is the live contiguous data
            // area; the producer lock gives this writer exclusive access to it,
            // and every offset is masked into range. Payload first, then a
            // committed (non-`BUSY`) header.
            unsafe {
                copy_in(base, self.data_size, self.mask, ppos + HDR_LEN, data);
                write_header(base, self.mask, ppos, len as u32);
            }
            // Publish: the consumer's `Acquire` load pairs with this store.
            self.producer().store(ppos + need, Ordering::Release);
        }
        narf_net::readiness::notify(0);
        Ok(())
    }

    /// Drain the next readable record, or `None` if the ring is caught up or its
    /// head record is still being written.
    ///
    /// The in-kernel consumer; a userspace consumer instead reads the `mmap`ed
    /// frames directly. Skips abandoned ([`DISCARD`]) records. Allocates the
    /// returned `Vec` — the `mmap` surface reads in place without copying.
    #[must_use]
    pub fn consume_one(&self) -> Option<Vec<u8>> {
        let base = self.data_ptr();
        loop {
            let cpos = self.consumer().load(Ordering::Relaxed);
            let ppos = self.producer().load(Ordering::Acquire);
            if cpos >= ppos {
                return None;
            }
            // SAFETY: `base` spans the live data area; the header at `cpos` is
            // within it and, being 8-aligned, never straddles the wrap.
            let len_word = unsafe { read_len_word(base, self.mask, cpos) };
            // A record still being written blocks everything behind it.
            if len_word & BUSY != 0 {
                return None;
            }
            let len = u64::from(len_word & LEN_MASK);
            let total = HDR_LEN + round_up8(len);
            if len_word & DISCARD != 0 {
                self.consumer().store(cpos + total, Ordering::Release);
                continue;
            }
            // SAFETY: same live data area; `[cpos + HDR_LEN, + len)` is a fully
            // written payload, published by the producer's `Release` store the
            // `Acquire` load above paired with.
            let out = unsafe {
                copy_out(
                    base,
                    self.data_size,
                    self.mask,
                    cpos + HDR_LEN,
                    len as usize,
                )
            };
            self.consumer().store(cpos + total, Ordering::Release);
            return Some(out);
        }
    }

    /// The number of pages a userspace `mmap` of this ring spans: the two
    /// control pages plus the data pages.
    #[must_use]
    pub fn mmap_page_count(&self) -> usize {
        2 + (self.data_size / PAGE) as usize
    }

    /// Physical frame addresses backing a userspace `mmap`, in the order
    /// userspace expects: the consumer page, the producer page, then each data
    /// page. One entry per 4 KiB page, exactly [`mmap_page_count`] long.
    ///
    /// [`mmap_page_count`]: Self::mmap_page_count
    #[must_use]
    pub fn mmap_frames(&self) -> Vec<u64> {
        let mut frames = Vec::with_capacity(self.mmap_page_count());
        let control = self.control.start_address().raw();
        frames.push(control);
        frames.push(control + PAGE);
        let data = self.data.start_address().raw();
        for i in 0..(self.data_size / PAGE) {
            frames.push(data + i * PAGE);
        }
        frames
    }
}

impl Drop for RingBuf {
    fn drop(&mut self) {
        free_pages(self.control, 1);
        free_pages(self.data, self.data_order);
    }
}

/// Write an 8-byte record header at `pos`. `pos` is 8-aligned and the header
/// never straddles the wrap, so this is a plain in-place write.
///
/// # Safety
///
/// `base` must point to a data area of at least `mask + 1` bytes to which the
/// caller holds exclusive write access; `pos & mask` addresses an in-range
/// 8-byte slot.
unsafe fn write_header(base: *mut u8, mask: u64, pos: u64, len: u32) {
    let off = (pos & mask) as usize;
    // SAFETY: forwarded — the 8-byte header lies wholly within the data area.
    unsafe {
        core::ptr::copy_nonoverlapping(len.to_le_bytes().as_ptr(), base.add(off), 4);
        // `pg_off`: only the mmap reverse-mapping consults it. Zero here.
        core::ptr::write_bytes(base.add(off + 4), 0, 4);
    }
}

/// Read a record's 4-byte length word (length + flags) at `pos`.
///
/// # Safety
///
/// As [`write_header`], for read access.
unsafe fn read_len_word(base: *const u8, mask: u64, pos: u64) -> u32 {
    let off = (pos & mask) as usize;
    let mut bytes = [0u8; 4];
    // SAFETY: forwarded — the 4-byte length word lies wholly within the area.
    unsafe { core::ptr::copy_nonoverlapping(base.add(off), bytes.as_mut_ptr(), 4) };
    u32::from_le_bytes(bytes)
}

/// Copy `src` into the ring at byte offset `start`, wrapping at the end.
///
/// # Safety
///
/// `base` addresses a `size`-byte data area (a power of two, `size == mask + 1`)
/// the caller may write exclusively; `src` fits within it.
unsafe fn copy_in(base: *mut u8, size: u64, mask: u64, start: u64, src: &[u8]) {
    let s = (start & mask) as usize;
    let first = core::cmp::min(src.len(), size as usize - s);
    // SAFETY: `s + first <= size` and, on wrap, `src.len() - first <= s`, so
    // both copies stay inside the data area.
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), base.add(s), first);
        if first < src.len() {
            core::ptr::copy_nonoverlapping(src.as_ptr().add(first), base, src.len() - first);
        }
    }
}

/// Copy `len` bytes out of the ring from byte offset `start`, wrapping.
///
/// # Safety
///
/// As [`copy_in`], for read access; `len <= size`.
unsafe fn copy_out(base: *const u8, size: u64, mask: u64, start: u64, len: usize) -> Vec<u8> {
    let s = (start & mask) as usize;
    let first = core::cmp::min(len, size as usize - s);
    let mut out = alloc::vec![0u8; len];
    // SAFETY: mirror of `copy_in`'s bounds; the destination `Vec` is `len` long.
    unsafe {
        core::ptr::copy_nonoverlapping(base.add(s), out.as_mut_ptr(), first);
        if first < len {
            core::ptr::copy_nonoverlapping(base, out.as_mut_ptr().add(first), len - first);
        }
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

    fn lookup_and_delete(&self, _key: &[u8], _out: &mut [u8]) -> Result<(), MapError> {
        Err(MapError::Unsupported)
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

// ── reserve / submit / discard ──────────────────────────────────────
//
// These three are **interpreter intrinsics**: the interpreter intercepts their
// ids and manipulates the VM's staged reservation directly, because a reserved
// record is VM-local state a plain kfunc shim has no handle on. They are
// registered as kfuncs all the same, so the verifier has their descriptors —
// and the descriptors are what enforce the whole contract (an acquired, sized,
// nullable region that must be submitted or discarded). The JIT refuses any
// program that calls them (see [`is_intrinsic`]), since native code cannot
// reach the VM state, so such a program always runs interpreted.

/// A byte region acquired from `bpf_ringbuf_reserve`.
///
/// `Option<ReservedRegion>` in return position spells `KF_ACQUIRE |
/// KF_RET_NULL`; a bare `ReservedRegion` in argument position (submit/discard)
/// releases it. The region's size is the reserve's `Const` size argument, which
/// the verifier reads to bound writes through it.
///
/// It holds the region's synthetic address, but the value is never
/// dereferenced here: the interpreter routes accesses to the staged buffer and
/// the shims below never run.
#[derive(Debug)]
pub struct ReservedRegion(u64);

// SAFETY: `from_raw` stores the register verbatim and never dereferences it;
// the interpreter is the only thing that turns the synthetic address into a
// real access, and it bounds every one against the reserved length.
unsafe impl BpfType for ReservedRegion {
    const DESC: ArgDesc = ArgDesc {
        kind: TypeKind::Ptr {
            kind: PtrKind::Mem,
            key: TypeKey::NONE,
        },
        domain: ValidityDomain::Owned,
        flags: ArgFlags::NONE,
    };
    #[inline]
    unsafe fn from_raw(raw: u64, _next: u64) -> Self {
        Self(raw)
    }
    #[inline]
    fn into_raw(self) -> u64 {
        self.0
    }
}

crate::kfunc! {
    /// Reserve a `size`-byte record in the ring buffer `map`, returning a
    /// writable region to fill and then hand to [`narf_ringbuf_submit`] or
    /// [`narf_ringbuf_discard`] — the `bpf_ringbuf_reserve` shape.
    ///
    /// `size` is a constant so the region can be bounded at verification time.
    /// Returns null if `flags` names an unknown bit, `map` is not a ring
    /// buffer, the record is too large to stage, or the ring is full — which is
    /// why the return is an `Option` the verifier makes the program test.
    ///
    /// This body is unreachable: the interpreter intercepts the call. It
    /// declines rather than panicking, so that if the interception is ever
    /// bypassed the failure is a null reservation, not a wild write.
    #[context(Atomic)]
    pub fn narf_ringbuf_reserve(
        map: crate::types::Trusted<crate::map::BpfMap>,
        size: crate::types::Const<u64>,
        flags: u64,
    ) -> Option<ReservedRegion> {
        let _ = (map, size, flags);
        None
    }

    /// Commit a reservation from [`narf_ringbuf_reserve`], making the record
    /// visible to the consumer — the `bpf_ringbuf_submit` shape. Consumes the
    /// region. Interpreter intrinsic; this body is unreachable.
    #[context(Atomic)]
    pub fn narf_ringbuf_submit(region: ReservedRegion, flags: u64) -> () {
        let _ = (region, flags);
    }

    /// Abandon a reservation from [`narf_ringbuf_reserve`] without publishing it
    /// — the `bpf_ringbuf_discard` shape. Consumes the region. Interpreter
    /// intrinsic; this body is unreachable.
    #[context(Atomic)]
    pub fn narf_ringbuf_discard(region: ReservedRegion, flags: u64) -> () {
        let _ = (region, flags);
    }
}

/// The kfunc id of `narf_ringbuf_reserve`, for the interpreter's interception
/// and the JIT's refusal. Derived from the name exactly as the registry's ids
/// are, so the two cannot drift.
pub const RESERVE_ID: i32 = crate::types::fnv1a32_nonzero("narf_ringbuf_reserve") as i32;
/// The kfunc id of `narf_ringbuf_submit`.
pub const SUBMIT_ID: i32 = crate::types::fnv1a32_nonzero("narf_ringbuf_submit") as i32;
/// The kfunc id of `narf_ringbuf_discard`.
pub const DISCARD_ID: i32 = crate::types::fnv1a32_nonzero("narf_ringbuf_discard") as i32;

/// Whether `id` names one of the reserve/submit/discard interpreter intrinsics.
/// The JIT refuses any program that calls one, so it runs interpreted.
#[must_use]
pub fn is_intrinsic(id: i32) -> bool {
    id == RESERVE_ID || id == SUBMIT_ID || id == DISCARD_ID
}

/// `bpf_ringbuf_reserve` wakeup-control flags — accepted and ignored (there is
/// no consumer to wake yet); any other bit makes the reservation fail.
pub const RESERVE_WAKEUP_FLAGS: u64 = 0b11;
