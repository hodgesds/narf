//! BPF maps — the four keyed kinds.
//!
//! `bpf/specification/spec.md` §3.4: five native kinds behind an ~8-method
//! trait, against Linux's 45-slot `bpf_map_ops` union. This module implements
//! four of them — [`MapKind::Array`], [`MapKind::Hash`],
//! [`MapKind::PerCpuArray`], [`MapKind::PerCpuHash`]. `RingBuf` is a stream
//! rather than a keyed store and does not fit this trait; it lands separately.
//!
//! LRU, LPM tries, bloom filters, queues/stacks, map-in-map and the whole
//! graph-data-structure API are **not** map types here. They become arena +
//! kfunc libraries, which is the whole reason the trait can be eight methods
//! wide.
//!
//! ## No allocation on the program-run path (spec §4.6)
//!
//! Every byte a map will ever use is allocated by [`BpfMap::create`]. Lookup,
//! update, delete and iteration are index arithmetic over pre-sized `Vec`s:
//! there is no `Vec::push`, no `BTreeMap::insert`, and no path to the global
//! allocator. That is not a micro-optimisation. A map operation can happen
//! from an XDP hook with IRQs masked and from `drain_irq_samples` with two
//! locks held, and an allocation failure there routes to `handle_alloc_error`
//! — a kernel panic driven by a program instruction.
//!
//! The hash table is therefore closed: a fixed node array with an intrusive
//! free list, `max_entries` nodes and a power-of-two bucket array, all sized
//! at creation. Insertion past `max_entries` is [`MapError::TooBig`]
//! (`E2BIG`), exactly as Linux's `htab_map_update_elem` reports a full table,
//! rather than growing.
//!
//! ## Locking
//!
//! One [`IrqSafeSpinLock`] per map guards all of its storage. It masks local
//! interrupts while held, so a probe firing on the same CPU cannot re-enter
//! it, and a program on another CPU spins. Spec §4.6 forbids taking "any
//! `IrqSafeSpinLock` a caller might hold" — a map's own lock is not one of
//! those: the map is reachable only from BPF, and no kernel path outside this
//! module takes it. Linux makes the same argument for `htab`'s
//! `raw_spin_lock`.
//!
//! What this does *not* buy is per-CPU lock scalability. Linux's per-CPU maps
//! are lock-free because each CPU addresses its own allocation; here the
//! per-CPU kinds give per-CPU *value semantics* — each CPU aggregates into its
//! own slot, so there are no lost updates and the syscall side can read all
//! CPUs — while still serialising on one lock. Splitting the lock per CPU is a
//! later change; it is deliberately not claimed here.
//!
//! An NMI-context program would deadlock on a lock its own CPU holds. NARF's
//! probe sites are not NMI, and the kfunc set is closed and audited (§4.7), so
//! there is no such caller to protect against today.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

/// Authority to create a BPF map.
///
/// The `CapKind` predates this module (`capabilities/src/lib.rs`). Liveness is
/// re-checked on every use rather than only at creation: holding a `Cap` proves
/// a prior grant, and only `check_live()` proves the grant has not since been
/// revoked.
#[derive(Copy, Clone, Debug)]
pub struct BpfMapCap;
impl CapType for BpfMapCap {
    const KIND: CapKind = CapKind::BpfMap;
}

/// The map kinds NARF implements: four keyed kinds and the ring buffer.
///
/// Discriminants are Linux's `enum bpf_map_type` values, so `kind as u32` is the
/// wire value with nothing in between to drift. The reverse direction still needs
/// a match — [`MapKind::from_linux`] — because most of Linux's values have no
/// kind here and turning an arbitrary `u32` into one has to be able to fail.
///
/// [`MapKind::RingBuf`] is the odd one out: it is not keyed and has no value
/// width, so it does not go through the element ops the other four share. See
/// [`crate::ringbuf`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MapKind {
    /// Open-keyed hash table, capacity `max_entries`.
    Hash = 1,
    /// Dense `u32`-keyed array. Every slot exists from creation; `delete` is
    /// not defined on it.
    Array = 2,
    /// [`MapKind::Hash`] with one value slot per CPU.
    PerCpuHash = 5,
    /// [`MapKind::Array`] with one value slot per CPU.
    PerCpuArray = 6,
    /// Multi-producer / single-consumer byte stream of variable-length
    /// records. Not keyed; reached through [`crate::ringbuf::RingBuf`].
    /// `max_entries` is the data-area size in bytes.
    RingBuf = 27,
}

impl MapKind {
    /// The kind for a Linux `enum bpf_map_type` value.
    #[must_use]
    pub const fn from_linux(v: u32) -> Option<MapKind> {
        match v {
            1 => Some(MapKind::Hash),
            2 => Some(MapKind::Array),
            5 => Some(MapKind::PerCpuHash),
            6 => Some(MapKind::PerCpuArray),
            27 => Some(MapKind::RingBuf),
            _ => None,
        }
    }

    /// Whether values are replicated per CPU.
    #[inline]
    #[must_use]
    pub const fn is_per_cpu(self) -> bool {
        matches!(self, MapKind::PerCpuHash | MapKind::PerCpuArray)
    }

    /// Whether keys are dense `u32` indices.
    #[inline]
    #[must_use]
    pub const fn is_array(self) -> bool {
        matches!(self, MapKind::Array | MapKind::PerCpuArray)
    }
}

/// A map's immutable shape.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MapAttr {
    /// Which kind.
    pub kind: MapKind,
    /// Key width in bytes. Exactly 4 for the array kinds.
    pub key_size: u32,
    /// Value width in bytes.
    pub value_size: u32,
    /// Capacity. For the array kinds, also the exclusive key bound.
    pub max_entries: u32,
}

/// Largest key a map may have, in bytes.
///
/// Linux caps it at `MAX_BPF_STACK` (512) because `bpf_map_update_elem` copies
/// the key through a stack buffer. NARF has no such copy, but the bound is a
/// memory bound worth keeping and matching Linux costs nothing.
pub const MAX_KEY_SIZE: u32 = 512;

/// Largest value a map may have, in bytes.
pub const MAX_VALUE_SIZE: u32 = 1 << 20;

/// Largest total allocation one map may make, in bytes.
///
/// A cap on the *product*, not just on the factors: `max_entries` and
/// `value_size` are both attacker-chosen and their product is what gets
/// allocated. Without this, `value_size = 1 MiB, max_entries = 1 M` asks for a
/// terabyte and either exhausts the heap or is denied by
/// `handle_alloc_error`-adjacent means — neither of which is an errno.
pub const MAX_MAP_BYTES: u64 = 64 << 20;

/// Why a map operation failed.
///
/// Each variant maps to exactly one Linux errno; [`MapError::errno`] is that
/// mapping and the `bpf(2)` handler has no second opinion.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MapError {
    /// No such key. `ENOENT`. Also `BPF_EXIST` against an absent key, and
    /// `GET_NEXT_KEY` past the last one.
    NotFound,
    /// `BPF_NOEXIST` against a key that is already present. `EEXIST`.
    Exists,
    /// The map is full, or an array index is past `max_entries`. `E2BIG`.
    TooBig,
    /// A malformed request: wrong key or value width, an undefined flag
    /// combination, or an operation the kind does not define (`delete` on an
    /// array — which is what Linux's `array_map_delete_elem` returns too).
    /// `EINVAL`.
    Invalid,
    /// The allocation at creation could not be satisfied. `ENOMEM`.
    NoMemory,
    /// A syscall tried to mutate a map after [`BpfMap::freeze`]. `EPERM`.
    /// Program-side updates deliberately remain permitted.
    Frozen,
    /// A freeze raced an active syscall writer, or the map was already
    /// frozen. `EBUSY`.
    Busy,
    /// The requested operation has no honest implementation for this map
    /// kind. `EOPNOTSUPP`.
    Unsupported,
    /// The `Cap<BpfMapCap, Grant>` was revoked. `EPERM`.
    AuthorityRevoked,
}

impl From<CapError> for MapError {
    fn from(_: CapError) -> Self {
        MapError::AuthorityRevoked
    }
}

impl MapError {
    /// The positive Linux errno for this failure.
    #[inline]
    #[must_use]
    pub const fn errno(self) -> u32 {
        match self {
            MapError::AuthorityRevoked => 1, // EPERM
            MapError::Frozen => 1,           // EPERM
            MapError::NotFound => 2,         // ENOENT
            MapError::Exists => 17,          // EEXIST
            MapError::Busy => 16,            // EBUSY
            MapError::Invalid => 22,         // EINVAL
            MapError::NoMemory => 12,        // ENOMEM
            MapError::TooBig => 7,           // E2BIG
            MapError::Unsupported => 95,     // EOPNOTSUPP
        }
    }
}

/// `BPF_ANY` — create or overwrite.
pub const BPF_ANY: u64 = 0;
/// `BPF_NOEXIST` — create only; `EEXIST` if the key is present.
pub const BPF_NOEXIST: u64 = 1;
/// `BPF_EXIST` — overwrite only; `ENOENT` if the key is absent.
pub const BPF_EXIST: u64 = 2;
/// `BPF_F_LOCK` — take the value's embedded `bpf_spin_lock` across the copy.
///
/// Accepted in the flag word and then rejected, because a value can only carry
/// a lock if BTF said where it is, and NARF has no in-kernel BTF. Linux
/// rejects it the same way for a map with no lock field
/// (`map_flags & BPF_F_LOCK` + `!btf_record_has_field(...)` ⇒ `EINVAL`), so
/// the errno is the same for the same reason.
pub const BPF_F_LOCK: u64 = 4;

/// The one map interface.
///
/// Eight methods. Linux's `bpf_map_ops` has 45 slots; the difference is that
/// nothing here is a hook for a map type that does not exist, and the four
/// kinds share one implementation of the syscall/program split rather than each
/// carrying its own `_percpu` variants.
///
/// Two lookup/update pairs, not one, because a per-CPU map genuinely has two
/// views and conflating them is how Linux ended up with
/// `bpf_percpu_array_copy` beside `array_map_lookup_elem`:
///
/// * [`BpfMapOps::lookup`] / [`BpfMapOps::update`] are the **syscall** view.
///   For a per-CPU kind the buffer covers every CPU, `cpus * stride` bytes;
///   [`BpfMapOps::syscall_value_bytes`] is that width.
/// * [`BpfMapOps::lookup_local`] / [`BpfMapOps::update_local`] are the
///   **program** view: this CPU's slot only, `value_size` bytes.
///
/// For the two non-per-CPU kinds the two views coincide, which is why the
/// `_local` pair has no default: an implementor that got them confused would
/// silently return another CPU's counter.
pub trait BpfMapOps: Send + Sync + core::fmt::Debug {
    /// The immutable shape.
    fn attr(&self) -> MapAttr;

    /// Bytes a syscall-level value buffer must have: `value_size` for the
    /// plain kinds, `cpus * round_up(value_size, 8)` for the per-CPU ones.
    fn syscall_value_bytes(&self) -> usize;

    /// Copy the value for `key` into `out` (all CPUs, for a per-CPU kind).
    ///
    /// # Errors
    ///
    /// [`MapError::NotFound`] if the key is absent, [`MapError::Invalid`] on a
    /// wrong-width buffer.
    fn lookup(&self, key: &[u8], out: &mut [u8]) -> Result<(), MapError>;

    /// Install `value` for `key`, honouring `flags` (all CPUs, for a per-CPU
    /// kind).
    ///
    /// # Errors
    ///
    /// See [`MapError`]; the flag errnos are `BPF_NOEXIST` ⇒
    /// [`MapError::Exists`] and `BPF_EXIST` ⇒ [`MapError::NotFound`].
    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), MapError>;

    /// Remove `key`.
    ///
    /// # Errors
    ///
    /// [`MapError::NotFound`] if absent; [`MapError::Invalid`] for the array
    /// kinds, which have no removable slots.
    fn delete(&self, key: &[u8]) -> Result<(), MapError>;

    /// Write the key after `key` — or the first key, when `key` is `None` — to
    /// `out`.
    ///
    /// # Errors
    ///
    /// [`MapError::NotFound`] when `key` is the last one, which is how
    /// iteration terminates.
    fn next_key(&self, key: Option<&[u8]>, out: &mut [u8]) -> Result<(), MapError>;

    /// Copy the calling CPU's value for `key` into `out` (`value_size` bytes).
    ///
    /// # Errors
    ///
    /// As [`BpfMapOps::lookup`].
    fn lookup_local(&self, key: &[u8], out: &mut [u8]) -> Result<(), MapError>;

    /// Install the calling CPU's value for `key` (`value_size` bytes).
    ///
    /// # Errors
    ///
    /// As [`BpfMapOps::update`].
    fn update_local(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), MapError>;
}

// ── shared helpers ──────────────────────────────────────────────────

/// Per-CPU value slots are 8-byte-strided, exactly as Linux's per-CPU maps
/// round `value_size` up to `sizeof(long)` so each CPU's slot stays aligned
/// for the atomic RMW a counter map is built for.
#[inline]
const fn stride_for(value_size: u32) -> usize {
    ((value_size as usize) + 7) & !7
}

/// A fallible zeroed allocation.
///
/// `vec![0; n]` aborts through `handle_alloc_error` when the heap cannot
/// satisfy it, which for a userspace-sized request is a kernel panic driven by
/// a syscall argument. `try_reserve_exact` turns it into an errno.
fn try_zeroed(n: usize) -> Result<Vec<u8>, MapError> {
    let mut v: Vec<u8> = Vec::new();
    v.try_reserve_exact(n).map_err(|_| MapError::NoMemory)?;
    // Cannot reallocate: capacity is already at least `n`.
    v.resize(n, 0);
    Ok(v)
}

fn try_filled_u32(n: usize, fill: u32) -> Result<Vec<u32>, MapError> {
    let mut v: Vec<u32> = Vec::new();
    v.try_reserve_exact(n).map_err(|_| MapError::NoMemory)?;
    v.resize(n, fill);
    Ok(v)
}

/// How many CPUs a per-CPU map replicates across.
///
/// Read once, at creation. `cpu_count()` is set by SMP discovery before any
/// user task exists and never grows afterwards, so the width is stable for the
/// map's life — which is what makes the bound check in
/// [`this_cpu`] a defensive one rather than a live failure mode.
fn cpu_width(kind: MapKind) -> usize {
    if kind.is_per_cpu() {
        narf_lib::smp::cpu_count().max(1) as usize
    } else {
        1
    }
}

/// The calling CPU's slot index, bounded by the width recorded at creation.
///
/// **Every caller resolves this while already holding the map's lock**, which
/// masks local interrupts and therefore pins the task to this CPU for the rest
/// of the operation. Reading it before taking the lock compiles and reads
/// correctly and is still wrong: a migration between the read and the lock
/// leaves the operation writing another CPU's slot, which shows up as a
/// misattributed counter rather than as a crash. Recording the index at acquire
/// time and re-deriving it later is the same bug one step along, and it has
/// bitten this tree twice.
///
/// Out-of-range fails rather than aliasing slot 0: silently merging two CPUs'
/// counters is the failure that looks like data and not like a bug. It is
/// unreachable while [`cpu_width`]'s note holds — `cpu_count()` is final before
/// any user task exists — and exists so a future hotplug path fails loudly.
#[inline]
fn this_cpu(width: usize) -> Result<usize, MapError> {
    let cpu = narf_lib::percpu::current_cpu();
    if cpu >= width {
        return Err(MapError::Invalid);
    }
    Ok(cpu)
}

/// Validate the shape a create request asks for, per-kind.
/// The largest ring-buffer data area, matching [`MAX_MAP_BYTES`]'s intent for
/// the keyed kinds: a per-map footprint cap so one fd cannot pin the kernel.
const MAX_RINGBUF_BYTES: u32 = 16 * 1024 * 1024;

/// Page size the ring-buffer data area must be a multiple of. A ring is
/// eventually `mmap`ed, and a mapping is page-granular, so a sub-page ring
/// could never be handed to userspace whole. 4 KiB on both supported arches.
const RINGBUF_PAGE: u32 = 4096;

/// Validate a `BPF_MAP_TYPE_RINGBUF` creation.
///
/// Mirrors Linux's `ringbuf_map_alloc`: no key, no value, and `max_entries`
/// (the data-area size) a non-zero power of two that is a page multiple.
fn check_ringbuf_attr(attr: MapAttr) -> Result<(), MapError> {
    if attr.key_size != 0 || attr.value_size != 0 {
        return Err(MapError::Invalid);
    }
    if attr.max_entries == 0
        || !attr.max_entries.is_power_of_two()
        || attr.max_entries % RINGBUF_PAGE != 0
    {
        return Err(MapError::Invalid);
    }
    if attr.max_entries > MAX_RINGBUF_BYTES {
        return Err(MapError::TooBig);
    }
    Ok(())
}

fn check_attr(attr: MapAttr) -> Result<(), MapError> {
    if attr.kind == MapKind::RingBuf {
        return check_ringbuf_attr(attr);
    }
    if attr.max_entries == 0 || attr.value_size == 0 || attr.key_size == 0 {
        return Err(MapError::Invalid);
    }
    if attr.key_size > MAX_KEY_SIZE {
        return Err(MapError::Invalid);
    }
    if attr.kind.is_array() && attr.key_size != 4 {
        // Linux's `array_map_alloc_check` requires exactly 4: the key *is* the
        // index.
        return Err(MapError::Invalid);
    }
    if attr.value_size > MAX_VALUE_SIZE {
        return Err(MapError::TooBig);
    }
    let cpus = cpu_width(attr.kind) as u64;
    // Per-entry cost: the value (replicated per CPU), the key, and the hash
    // table's three side arrays — `link` (4 bytes), `live` (1), and up to two
    // bucket slots (8), since `buckets` is `max_entries` rounded up to a power
    // of two. 16 rather than 13 so the bound stays an over-estimate if a side
    // array is ever widened; it is a cap, and a cap that under-counts is one
    // that admits a map larger than it promised.
    let per_entry = stride_for(attr.value_size) as u64 * cpus + u64::from(attr.key_size) + 16;
    if per_entry.saturating_mul(u64::from(attr.max_entries)) > MAX_MAP_BYTES {
        return Err(MapError::TooBig);
    }
    Ok(())
}

/// Reject a flag word no kind accepts.
///
/// Linux: `if ((map_flags & ~BPF_F_LOCK) > BPF_EXIST) return -EINVAL;` — so a
/// flag word of 3 (`NOEXIST | EXIST`) is `EINVAL`, and `BPF_F_LOCK` is
/// separately rejected here because no NARF map value can carry a lock (no
/// BTF, so nothing says where it would live).
fn check_update_flags(flags: u64) -> Result<(), MapError> {
    if flags & BPF_F_LOCK != 0 {
        return Err(MapError::Invalid);
    }
    if flags > BPF_EXIST {
        return Err(MapError::Invalid);
    }
    Ok(())
}

// ── Array / PerCpuArray ─────────────────────────────────────────────

/// Dense `u32`-keyed storage. [`MapKind::Array`] and
/// [`MapKind::PerCpuArray`].
#[derive(Debug)]
pub struct ArrayMap {
    attr: MapAttr,
    stride: usize,
    cpus: usize,
    /// `max_entries * cpus * stride` bytes, all live from creation.
    slots: IrqSafeSpinLock<Vec<u8>>,
}

impl ArrayMap {
    /// Allocate an array map.
    ///
    /// # Errors
    ///
    /// [`MapError::Invalid`] for a malformed shape, [`MapError::TooBig`] for
    /// one past [`MAX_MAP_BYTES`], [`MapError::NoMemory`] if the heap cannot
    /// satisfy it.
    pub fn new(attr: MapAttr) -> Result<Self, MapError> {
        check_attr(attr)?;
        let stride = stride_for(attr.value_size);
        let cpus = cpu_width(attr.kind);
        let bytes = stride
            .checked_mul(cpus)
            .and_then(|n| n.checked_mul(attr.max_entries as usize))
            .ok_or(MapError::TooBig)?;
        Ok(Self {
            attr,
            stride,
            cpus,
            slots: IrqSafeSpinLock::new(try_zeroed(bytes)?),
        })
    }

    /// The index a 4-byte key names, or `None` if it is past `max_entries`.
    fn index(&self, key: &[u8]) -> Result<Option<usize>, MapError> {
        if key.len() != 4 {
            return Err(MapError::Invalid);
        }
        let i = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        if i >= self.attr.max_entries {
            return Ok(None);
        }
        Ok(Some(i as usize))
    }

    fn slot_range(&self, index: usize, cpu: usize) -> core::ops::Range<usize> {
        let base = (index * self.cpus + cpu) * self.stride;
        base..base + self.attr.value_size as usize
    }

    /// Which slot the program view addresses. Slot 0 for a non-per-CPU kind,
    /// which has exactly one.
    ///
    /// Call only with the map's lock held — see [`this_cpu`].
    fn local_cpu(&self) -> Result<usize, MapError> {
        if self.attr.kind.is_per_cpu() {
            this_cpu(self.cpus)
        } else {
            Ok(0)
        }
    }
}

impl BpfMapOps for ArrayMap {
    fn attr(&self) -> MapAttr {
        self.attr
    }

    fn syscall_value_bytes(&self) -> usize {
        if self.attr.kind.is_per_cpu() {
            self.stride * self.cpus
        } else {
            self.attr.value_size as usize
        }
    }

    fn lookup(&self, key: &[u8], out: &mut [u8]) -> Result<(), MapError> {
        if out.len() != self.syscall_value_bytes() {
            return Err(MapError::Invalid);
        }
        // A key past `max_entries` is a *missing* key, not an oversized
        // request: Linux's `array_map_lookup_elem` returns NULL and the
        // syscall turns that into `ENOENT`. Only `update` reports `E2BIG`.
        let index = self.index(key)?.ok_or(MapError::NotFound)?;
        let g = self.slots.lock();
        if self.attr.kind.is_per_cpu() {
            for cpu in 0..self.cpus {
                let r = self.slot_range(index, cpu);
                let d = cpu * self.stride;
                out[d..d + self.attr.value_size as usize].copy_from_slice(&g[r]);
            }
        } else {
            out.copy_from_slice(&g[self.slot_range(index, 0)]);
        }
        Ok(())
    }

    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), MapError> {
        check_update_flags(flags)?;
        if value.len() != self.syscall_value_bytes() {
            return Err(MapError::Invalid);
        }
        // Order matters and is Linux's: the index bound is checked before the
        // flags, so an out-of-range index with `BPF_NOEXIST` is `E2BIG` and
        // not `EEXIST`.
        let index = self.index(key)?.ok_or(MapError::TooBig)?;
        // Every array slot exists from creation, so "create only" can never be
        // satisfied. `array_map_update_elem` returns `EEXIST` unconditionally
        // for it.
        if flags == BPF_NOEXIST {
            return Err(MapError::Exists);
        }
        let mut g = self.slots.lock();
        if self.attr.kind.is_per_cpu() {
            for cpu in 0..self.cpus {
                let r = self.slot_range(index, cpu);
                let d = cpu * self.stride;
                g[r].copy_from_slice(&value[d..d + self.attr.value_size as usize]);
            }
        } else {
            let r = self.slot_range(index, 0);
            g[r].copy_from_slice(value);
        }
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), MapError> {
        // Shape-check the key anyway: a caller passing a 1-byte key to an
        // array map has a bug worth naming, and `EINVAL` is the answer either
        // way.
        let _ = self.index(key)?;
        // `array_map_delete_elem` is `-EINVAL`: an array slot cannot stop
        // existing.
        Err(MapError::Invalid)
    }

    fn next_key(&self, key: Option<&[u8]>, out: &mut [u8]) -> Result<(), MapError> {
        if out.len() != 4 {
            return Err(MapError::Invalid);
        }
        // `array_map_get_next_key`, verbatim: a `None` key (Linux's NULL) and
        // an out-of-range key both restart at 0; the last index is `ENOENT`.
        let index = match key {
            None => None,
            Some(k) => self.index(k)?,
        };
        let next = match index {
            None => 0,
            Some(i) if i as u32 == self.attr.max_entries - 1 => return Err(MapError::NotFound),
            Some(i) => i as u32 + 1,
        };
        out.copy_from_slice(&next.to_le_bytes());
        Ok(())
    }

    fn lookup_local(&self, key: &[u8], out: &mut [u8]) -> Result<(), MapError> {
        if out.len() != self.attr.value_size as usize {
            return Err(MapError::Invalid);
        }
        let index = self.index(key)?.ok_or(MapError::NotFound)?;
        let g = self.slots.lock();
        let cpu = self.local_cpu()?;
        out.copy_from_slice(&g[self.slot_range(index, cpu)]);
        Ok(())
    }

    fn update_local(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), MapError> {
        check_update_flags(flags)?;
        if value.len() != self.attr.value_size as usize {
            return Err(MapError::Invalid);
        }
        let index = self.index(key)?.ok_or(MapError::TooBig)?;
        if flags == BPF_NOEXIST {
            return Err(MapError::Exists);
        }
        let mut g = self.slots.lock();
        let cpu = self.local_cpu()?;
        let r = self.slot_range(index, cpu);
        g[r].copy_from_slice(value);
        Ok(())
    }
}

// ── Hash / PerCpuHash ───────────────────────────────────────────────

/// "No node".
const NIL: u32 = u32::MAX;

/// The closed hash table's mutable state.
///
/// A fixed node array plus a power-of-two bucket array. `link` serves double
/// duty — bucket chain for a live node, free list for a dead one — which is
/// sound because a node is in exactly one of the two at any time and is what
/// keeps the whole structure to three integer arrays.
#[derive(Debug)]
struct HashStore {
    /// Head node index per bucket, or [`NIL`].
    buckets: Vec<u32>,
    /// Next node in this node's bucket chain, or next free node.
    link: Vec<u32>,
    /// `max_entries * key_size`.
    keys: Vec<u8>,
    /// `max_entries * cpus * stride`.
    values: Vec<u8>,
    /// Whether node `i` holds a live entry. Needed separately from the free
    /// list because iteration walks the node array in index order and has to
    /// distinguish a live node from a free one in O(1).
    live: Vec<bool>,
    /// Head of the free list, or [`NIL`] when the table is full.
    free: u32,
    /// Live entries.
    count: u32,
}

/// Open-keyed storage. [`MapKind::Hash`] and [`MapKind::PerCpuHash`].
#[derive(Debug)]
pub struct HashMap {
    attr: MapAttr,
    stride: usize,
    cpus: usize,
    mask: u32,
    store: IrqSafeSpinLock<HashStore>,
}

/// FNV-1a over the key bytes.
///
/// Not a keyed hash. Linux seeds `htab->hashrnd` from
/// `get_random_u32()` because an unprivileged program could otherwise pick
/// colliding keys and turn a bucket into a linked list. NARF has no
/// unprivileged BPF at all (spec §4.10), and every key that reaches this
/// function came from a euid-0 caller, so the collision-resistance argument has
/// no adversary. Seeding it would still be cheap; it is left out because
/// pretending a random seed is a security property when the caller is already
/// root is the kind of comment this tree does not want.
fn hash_key(key: &[u8]) -> u32 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Fold to 32 bits so the high-entropy half contributes to the bucket
    // index; the low bits of an FNV hash over short keys are the ones that
    // vary least.
    ((h >> 32) ^ h) as u32
}

impl HashMap {
    /// Allocate a hash map.
    ///
    /// # Errors
    ///
    /// As [`ArrayMap::new`].
    pub fn new(attr: MapAttr) -> Result<Self, MapError> {
        check_attr(attr)?;
        let stride = stride_for(attr.value_size);
        let cpus = cpu_width(attr.kind);
        let n = attr.max_entries as usize;
        // A power-of-two bucket count at least as large as the capacity, so
        // the load factor never exceeds 1 and the index is a mask rather than
        // a division.
        let buckets = (attr.max_entries as usize).next_power_of_two();
        let value_bytes = stride
            .checked_mul(cpus)
            .and_then(|s| s.checked_mul(n))
            .ok_or(MapError::TooBig)?;
        let key_bytes = (attr.key_size as usize)
            .checked_mul(n)
            .ok_or(MapError::TooBig)?;

        // The free list is the whole node array, threaded in index order so
        // that a fresh map hands out node 0 first and iteration order matches
        // insertion order until the first delete.
        let mut link = try_filled_u32(n, NIL)?;
        for (i, l) in link.iter_mut().enumerate() {
            *l = if i + 1 < n { i as u32 + 1 } else { NIL };
        }
        let mut live: Vec<bool> = Vec::new();
        live.try_reserve_exact(n).map_err(|_| MapError::NoMemory)?;
        live.resize(n, false);

        Ok(Self {
            attr,
            stride,
            cpus,
            mask: (buckets - 1) as u32,
            store: IrqSafeSpinLock::new(HashStore {
                buckets: try_filled_u32(buckets, NIL)?,
                link,
                keys: try_zeroed(key_bytes)?,
                values: try_zeroed(value_bytes)?,
                live,
                free: 0,
                count: 0,
            }),
        })
    }

    /// Live entries. Not on the trait — the trait is what a program and the
    /// syscall need, and neither asks this; the smokes do.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.store.lock().count
    }

    /// Whether the map holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn key_range(&self, node: usize) -> core::ops::Range<usize> {
        let ks = self.attr.key_size as usize;
        node * ks..node * ks + ks
    }

    fn value_range(&self, node: usize, cpu: usize) -> core::ops::Range<usize> {
        let base = (node * self.cpus + cpu) * self.stride;
        base..base + self.attr.value_size as usize
    }

    fn bucket_of(&self, key: &[u8]) -> usize {
        (hash_key(key) & self.mask) as usize
    }

    /// Which slot the program view addresses; see [`ArrayMap::local_cpu`].
    ///
    /// Call only with the map's lock held — see [`this_cpu`].
    fn local_cpu(&self) -> Result<usize, MapError> {
        if self.attr.kind.is_per_cpu() {
            this_cpu(self.cpus)
        } else {
            Ok(0)
        }
    }

    /// The node holding `key`, or `None`.
    fn find(&self, st: &HashStore, key: &[u8]) -> Option<usize> {
        let mut n = st.buckets[self.bucket_of(key)];
        while n != NIL {
            let i = n as usize;
            if st.keys[self.key_range(i)] == *key {
                return Some(i);
            }
            n = st.link[i];
        }
        None
    }

    /// Claim a free node for `key` and link it into its bucket.
    fn insert_node(&self, st: &mut HashStore, key: &[u8]) -> Result<usize, MapError> {
        if st.free == NIL {
            // The table is full. Linux's `htab_map_update_elem` reports the
            // same condition as `E2BIG` after its `count > max_entries` test.
            return Err(MapError::TooBig);
        }
        let node = st.free as usize;
        st.free = st.link[node];
        let b = self.bucket_of(key);
        st.link[node] = st.buckets[b];
        st.buckets[b] = node as u32;
        st.live[node] = true;
        st.count += 1;
        let r = self.key_range(node);
        st.keys[r].copy_from_slice(key);
        Ok(node)
    }

    fn unlink_node(&self, st: &mut HashStore, key: &[u8], node: usize) {
        let b = self.bucket_of(key);
        let mut cur = st.buckets[b];
        if cur == node as u32 {
            st.buckets[b] = st.link[node];
        } else {
            while cur != NIL {
                let i = cur as usize;
                if st.link[i] == node as u32 {
                    st.link[i] = st.link[node];
                    break;
                }
                cur = st.link[i];
            }
        }
        st.live[node] = false;
        st.link[node] = st.free;
        st.free = node as u32;
        st.count -= 1;
        // Zero the value so a recycled node cannot hand a later key the
        // previous occupant's bytes. `BPF_NOEXIST`-created entries are
        // fully written by the caller, but `update_local` on a per-CPU map
        // writes one CPU's slot only, so the others would otherwise be stale.
        for cpu in 0..self.cpus {
            let r = self.value_range(node, cpu);
            st.values[r].fill(0);
        }
    }

    /// Apply the create/overwrite flag policy, returning the node to write.
    fn resolve_update(
        &self,
        st: &mut HashStore,
        key: &[u8],
        flags: u64,
    ) -> Result<usize, MapError> {
        match (self.find(st, key), flags) {
            (Some(_), BPF_NOEXIST) => Err(MapError::Exists),
            (Some(n), _) => Ok(n),
            (None, BPF_EXIST) => Err(MapError::NotFound),
            (None, _) => self.insert_node(st, key),
        }
    }

    fn check_key(&self, key: &[u8]) -> Result<(), MapError> {
        if key.len() != self.attr.key_size as usize {
            return Err(MapError::Invalid);
        }
        Ok(())
    }
}

impl BpfMapOps for HashMap {
    fn attr(&self) -> MapAttr {
        self.attr
    }

    fn syscall_value_bytes(&self) -> usize {
        if self.attr.kind.is_per_cpu() {
            self.stride * self.cpus
        } else {
            self.attr.value_size as usize
        }
    }

    fn lookup(&self, key: &[u8], out: &mut [u8]) -> Result<(), MapError> {
        self.check_key(key)?;
        if out.len() != self.syscall_value_bytes() {
            return Err(MapError::Invalid);
        }
        let st = self.store.lock();
        let node = self.find(&st, key).ok_or(MapError::NotFound)?;
        if self.attr.kind.is_per_cpu() {
            for cpu in 0..self.cpus {
                let r = self.value_range(node, cpu);
                let d = cpu * self.stride;
                out[d..d + self.attr.value_size as usize].copy_from_slice(&st.values[r]);
            }
        } else {
            out.copy_from_slice(&st.values[self.value_range(node, 0)]);
        }
        Ok(())
    }

    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), MapError> {
        check_update_flags(flags)?;
        self.check_key(key)?;
        if value.len() != self.syscall_value_bytes() {
            return Err(MapError::Invalid);
        }
        let mut st = self.store.lock();
        let node = self.resolve_update(&mut st, key, flags)?;
        if self.attr.kind.is_per_cpu() {
            for cpu in 0..self.cpus {
                let r = self.value_range(node, cpu);
                let d = cpu * self.stride;
                st.values[r].copy_from_slice(&value[d..d + self.attr.value_size as usize]);
            }
        } else {
            let r = self.value_range(node, 0);
            st.values[r].copy_from_slice(value);
        }
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), MapError> {
        self.check_key(key)?;
        let mut st = self.store.lock();
        let node = self.find(&st, key).ok_or(MapError::NotFound)?;
        self.unlink_node(&mut st, key, node);
        Ok(())
    }

    fn next_key(&self, key: Option<&[u8]>, out: &mut [u8]) -> Result<(), MapError> {
        if out.len() != self.attr.key_size as usize {
            return Err(MapError::Invalid);
        }
        if let Some(k) = key {
            self.check_key(k)?;
        }
        let st = self.store.lock();
        // Iteration walks the node array in index order.
        //
        // LINUX-GAP: Linux walks bucket by bucket
        // (`htab_map_get_next_key`), so the sequence differs. No order is part
        // of the ABI — `bpf_map_get_next_key` promises only that a full walk
        // with no concurrent modification visits every key once — and both
        // orders satisfy that. What *is* copied exactly is the quirk that
        // matters to callers: a key the map does not hold restarts the walk at
        // the first key rather than failing, because that is how libbpf's
        // delete-while-iterating loop keeps going.
        let from = match key.and_then(|k| self.find(&st, k)) {
            Some(n) => n + 1,
            None => 0,
        };
        for (i, live) in st.live.iter().enumerate().skip(from) {
            if *live {
                out.copy_from_slice(&st.keys[self.key_range(i)]);
                return Ok(());
            }
        }
        Err(MapError::NotFound)
    }

    fn lookup_local(&self, key: &[u8], out: &mut [u8]) -> Result<(), MapError> {
        self.check_key(key)?;
        if out.len() != self.attr.value_size as usize {
            return Err(MapError::Invalid);
        }
        let st = self.store.lock();
        let cpu = self.local_cpu()?;
        let node = self.find(&st, key).ok_or(MapError::NotFound)?;
        out.copy_from_slice(&st.values[self.value_range(node, cpu)]);
        Ok(())
    }

    fn update_local(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), MapError> {
        check_update_flags(flags)?;
        self.check_key(key)?;
        if value.len() != self.attr.value_size as usize {
            return Err(MapError::Invalid);
        }
        let mut st = self.store.lock();
        let cpu = self.local_cpu()?;
        let node = self.resolve_update(&mut st, key, flags)?;
        let r = self.value_range(node, cpu);
        st.values[r].copy_from_slice(value);
        Ok(())
    }
}

// ── the map object ──────────────────────────────────────────────────

static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// A created map: an id, a name, and one of the four implementations.
///
/// Reference-counted for the same reason [`crate::prog::BpfProg`] is: the fd
/// owns the reference a program holds, and a program outlives the fd it was
/// created through.
#[derive(Debug)]
pub struct BpfMap {
    /// Kernel-wide id.
    pub id: u32,
    /// Name as supplied at creation, at most 16 bytes.
    pub name: alloc::string::String,
    ops: MapImpl,
    /// Bytes charged to the creating task's cgroup, to uncharge on drop.
    charged: u64,
    /// References currently held by running BPF programs — see
    /// [`MAX_BPF_PINS`] and [`narf_map_acquire`].
    bpf_pins: AtomicU32,
    /// Serialises the userspace-write side of `BPF_MAP_FREEZE`.
    ///
    /// Program writes do not enter this state: Linux's freeze contract blocks
    /// future syscall mutations while explicitly leaving BPF-program updates
    /// possible. `active` makes freeze fail with `EBUSY` rather than returning
    /// while an already-admitted syscall write can still commit.
    freeze: IrqSafeSpinLock<FreezeState>,
}

#[derive(Copy, Clone, Debug, Default)]
struct FreezeState {
    frozen: bool,
    active: u32,
}

/// One admitted userspace mutation of a map.
///
/// Created by [`BpfMap::begin_sys_write`]. Holding it pins the map's freeze
/// state in the "writer active" condition; dropping it releases that claim.
/// The only mutating methods exposed here are the syscall view. Program-side
/// kfuncs deliberately use the private operations table directly, because
/// `BPF_MAP_FREEZE` does not make a map read-only to BPF programs.
#[derive(Debug)]
pub struct SysWrite<'a> {
    map: &'a BpfMap,
}

impl SysWrite<'_> {
    /// Install a syscall-width value.
    pub fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), MapError> {
        self.map.ops().update(key, value, flags)
    }

    /// Delete one key through the syscall view.
    pub fn delete(&self, key: &[u8]) -> Result<(), MapError> {
        self.map.ops().delete(key)
    }
}

impl Drop for SysWrite<'_> {
    fn drop(&mut self) {
        let mut state = self.map.freeze.lock();
        debug_assert!(state.active != 0, "BPF map syscall-writer count underflow");
        state.active = state.active.saturating_sub(1);
    }
}

/// How many references one map may have out to BPF programs at once.
///
/// A program can call [`narf_map_acquire`] in a loop, and every call is an
/// `Arc` increment. Unbounded, a long-running program overflows the refcount
/// and the wrap frees a live map — the shape of a whole family of Linux
/// refcount bugs, and why `bpf_map_inc_not_zero` and its neighbours are
/// bounded there too.
///
/// The bound is what makes the acquire *fallible*, and therefore what makes
/// `Option<Owned<BpfMap>>` — and the null-check obligation the verifier hangs
/// on it — honest rather than decorative. An infallible acquire would have
/// wanted a bare `Owned<BpfMap>` return, and the program would have had
/// nothing to test.
///
/// // LINUX-GAP: Linux's bound is `INT_MAX`-ish and enforced by refusing to
/// increment past it; this is far lower, because the only legitimate holder
/// of a BPF pin is a program that is *currently running* and the verifier
/// requires it to release before exit. A program needing a thousand
/// simultaneous references to one map is doing something the reference model
/// does not have in mind.
pub const MAX_BPF_PINS: u32 = 1024;

/// Static dispatch over the four kinds.
///
/// An enum rather than `Box<dyn BpfMapOps>` because the program-facing path
/// runs with IRQs masked and this keeps ownership concrete. The private
/// [`BpfMap::ops`] projection is shared by the program kfuncs and the public,
/// freeze-aware syscall-view methods.
#[derive(Debug)]
enum MapImpl {
    Array(ArrayMap),
    Hash(HashMap),
    RingBuf(crate::ringbuf::RingBuf),
}

impl BpfMap {
    /// Create a map.
    ///
    /// `cap` is checked live on every entry, not merely presented: a `Cap` in
    /// hand proves a past grant and nothing about the present one.
    ///
    /// # Errors
    ///
    /// [`MapError::AuthorityRevoked`] if the capability is dead, otherwise as
    /// [`ArrayMap::new`] / [`HashMap::new`].
    pub fn create(
        cap: &Cap<BpfMapCap, Grant>,
        attr: MapAttr,
        name: alloc::string::String,
    ) -> Result<Arc<Self>, MapError> {
        cap.check_live()?;
        check_attr(attr)?;
        let charged = footprint_bytes(attr);
        // Charged before the allocation commits, and uncharged in `Drop`, so a
        // task cannot pin unbounded kernel memory behind an fd it owns. The
        // hook denies when a level is over `memory.max`, exactly as it does
        // for a frame allocation.
        //
        // Both directions attribute to whichever task is *running*, because
        // that is the only identity `cgroup_charge` has. A map dropped by a
        // task other than its creator therefore credits the wrong chain — the
        // same asymmetry a frame freed by another task already has, and the
        // reason this is a footprint cap rather than a precise accounting.
        // What it does enforce is the bound that matters: the charge is taken
        // from the creator, before the memory exists, and is refused when that
        // creator is already at its limit.
        if !charge(charged) {
            return Err(MapError::NoMemory);
        }
        let built = match attr.kind {
            MapKind::Array | MapKind::PerCpuArray => ArrayMap::new(attr).map(MapImpl::Array),
            MapKind::Hash | MapKind::PerCpuHash => HashMap::new(attr).map(MapImpl::Hash),
            // Frame-backed, and its own cgroup accountant (see
            // `footprint_bytes`): fallible if the frames cannot be allocated.
            MapKind::RingBuf => crate::ringbuf::RingBuf::new(attr).map(MapImpl::RingBuf),
        };
        let ops = match built {
            Ok(o) => o,
            Err(e) => {
                uncharge(charged);
                return Err(e);
            }
        };
        let map = Arc::new(Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            name,
            ops,
            charged,
            bpf_pins: AtomicU32::new(0),
            freeze: IrqSafeSpinLock::new(FreezeState::default()),
        });
        // Publish the id → map direction for `BPF_MAP_GET_FD_BY_ID`. Same
        // reasoning as `BpfProg::load_with_arena`: registering here rather than
        // in the `bpf(2)` handler means every map that has an id is reachable
        // by it, whoever created it.
        crate::idreg::maps().insert(map.id, &map);
        Ok(map)
    }

    /// The private operations table.
    ///
    /// A ring buffer answers this too — with an ops table that refuses every
    /// element command as `EINVAL`, which is what makes `BPF_MAP_LOOKUP_ELEM`
    /// and friends on a ring-buffer fd fail cleanly rather than needing a
    /// special case at every call site. Keeping this crate-private is what
    /// prevents another crate from bypassing [`BpfMap::begin_sys_write`] for a
    /// userspace mutation after freeze.
    #[must_use]
    pub(crate) fn ops(&self) -> &dyn BpfMapOps {
        match &self.ops {
            MapImpl::Array(a) => a,
            MapImpl::Hash(h) => h,
            MapImpl::RingBuf(r) => r,
        }
    }

    /// The ring buffer behind this map, or `None` if it is a keyed kind.
    ///
    /// The seam the producer path (`bpf_ringbuf_output`) and the consumer paths
    /// ([`MapFile`]'s `mmap`/`poll`, and the in-kernel `consume_one`) reach the
    /// stream through, since it is not part of the keyed [`BpfMapOps`] surface.
    #[must_use]
    pub fn ringbuf(&self) -> Option<&crate::ringbuf::RingBuf> {
        match &self.ops {
            MapImpl::RingBuf(r) => Some(r),
            _ => None,
        }
    }

    /// The immutable shape.
    #[must_use]
    pub fn attr(&self) -> MapAttr {
        self.ops().attr()
    }

    /// Bytes in the userspace view of one value.
    #[must_use]
    pub fn syscall_value_bytes(&self) -> usize {
        self.ops().syscall_value_bytes()
    }

    /// Read one value through the syscall view.
    pub fn lookup(&self, key: &[u8], out: &mut [u8]) -> Result<(), MapError> {
        self.ops().lookup(key, out)
    }

    /// Return the key following `key` through the syscall view.
    pub fn next_key(&self, key: Option<&[u8]>, out: &mut [u8]) -> Result<(), MapError> {
        self.ops().next_key(key, out)
    }

    /// Admit one syscall mutation and hold its active-writer claim until the
    /// returned guard is dropped.
    ///
    /// # Errors
    ///
    /// [`MapError::Frozen`] after a successful [`BpfMap::freeze`].
    pub fn begin_sys_write(&self) -> Result<SysWrite<'_>, MapError> {
        let mut state = self.freeze.lock();
        if state.frozen {
            return Err(MapError::Frozen);
        }
        state.active = state.active.checked_add(1).ok_or(MapError::Busy)?;
        Ok(SysWrite { map: self })
    }

    /// Permanently block future syscall-side map mutations.
    ///
    /// Program-side updates remain legal. Repeating the operation, or racing
    /// an already admitted syscall writer, returns [`MapError::Busy`]. Ring
    /// buffers are refused because NARF does not yet account their writable
    /// consumer-page mappings as active userspace writers; claiming to freeze
    /// one would leave an existing mapping able to mutate it.
    pub fn freeze(&self) -> Result<(), MapError> {
        if self.ringbuf().is_some() {
            return Err(MapError::Unsupported);
        }
        let mut state = self.freeze.lock();
        if state.frozen || state.active != 0 {
            return Err(MapError::Busy);
        }
        state.frozen = true;
        Ok(())
    }

    /// Whether [`BpfMap::freeze`] has completed successfully.
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        self.freeze.lock().frozen
    }

    /// How many references running BPF programs currently hold.
    ///
    /// Separate from the `Arc` strong count, which also moves for fds and for
    /// `BpfProg::maps` and so cannot distinguish "the program released" from
    /// "someone closed an fd". This one counts exactly the acquires that must
    /// be matched by a release, which is what makes the pair observable from a
    /// test at all.
    #[must_use]
    pub fn bpf_pins(&self) -> u32 {
        self.bpf_pins.load(Ordering::Relaxed)
    }

    /// Claim one BPF pin, refusing at [`MAX_BPF_PINS`].
    ///
    /// A CAS loop rather than a `fetch_add` with an after-the-fact check: an
    /// unconditional add is momentarily over the cap, and a concurrent reader
    /// of `bpf_pins()` would see a count the invariant says cannot happen.
    fn pin(&self) -> bool {
        self.bpf_pins
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_BPF_PINS).then_some(n + 1)
            })
            .is_ok()
    }
}

/// A map is the pointee of the opaque handle `LD_IMM64`'s map pseudo-forms
/// produce, and therefore what a map-access kfunc receives.
///
/// The `TypeKey` has to agree with the one the verifier stamps on that handle,
/// and the verifier cannot see this `impl` — so the name is declared there and
/// the assertion below is what makes drift a compile error rather than a
/// silently unresolvable kfunc argument.
impl crate::types::BpfObject for BpfMap {
    const TYPE_NAME: &'static str = narf_bpf_verifier::MAP_HANDLE_TYPE_NAME;

    unsafe fn release_owned(ptr: *mut Self) {
        // The pin comes off *before* the strong count, because the strong
        // count is what keeps `ptr` dereferenceable — touching `bpf_pins`
        // afterwards would be a use-after-free in exactly the case
        // `narf_map_acquire`'s note argues cannot arise, which is not a good
        // enough reason to write it in that order.
        //
        // SAFETY: the caller transfers a reference it owns, so the map is live
        // for the duration of this call.
        unsafe { (*ptr).bpf_pins.fetch_sub(1, Ordering::AcqRel) };
        // SAFETY: `ptr` is the data pointer of the same `Arc<BpfMap>`
        // allocation `narf_map_acquire` incremented — `Vm::map_addr` hands out
        // `Arc::as_ptr`, which is the pointer `Arc::into_raw` would produce —
        // and it carries the strong reference that increment took.
        unsafe { Arc::decrement_strong_count(ptr.cast_const()) };
    }
}

const _: () = assert!(
    <BpfMap as crate::types::BpfObject>::TYPE_KEY.0 == narf_bpf_verifier::MAP_HANDLE_TYPE_KEY.0,
    "the map handle's TypeKey disagrees with the one the verifier stamps on \
     `LD_IMM64`'s map pseudo-forms; a map-access kfunc would reject every map"
);

impl Drop for BpfMap {
    fn drop(&mut self) {
        // Prune the id entry before the charge is released — order does not
        // matter for correctness, but keeping the registry edit adjacent to the
        // `create` that inserted it is what stops the pair drifting apart.
        crate::idreg::maps().remove(self.id);
        uncharge(self.charged);
    }
}

/// Charge a map's footprint to the creating task's cgroup chain.
///
/// `true` when the charge is allowed — including in a kernel built without the
/// memory controller, where there is nothing to charge against. Wrapped rather
/// than `#[cfg]`-ed at each call site so `BpfMap`'s create/failure/drop triple
/// cannot end up with the arms gated inconsistently, which is the way a
/// cfg-gated charge/uncharge pair leaks.
fn charge(bytes: u64) -> bool {
    #[cfg(feature = "cgroup")]
    {
        narf_memory::cgroup_charge::try_charge(bytes)
    }
    #[cfg(not(feature = "cgroup"))]
    {
        let _ = bytes;
        true
    }
}

/// Release a charge taken by [`charge`].
fn uncharge(bytes: u64) {
    #[cfg(feature = "cgroup")]
    {
        narf_memory::cgroup_charge::uncharge(bytes);
    }
    #[cfg(not(feature = "cgroup"))]
    {
        let _ = bytes;
    }
}

/// What a map of this shape allocates, for accounting.
///
/// Computed from the shape rather than measured after the fact, because the
/// charge has to happen *before* the allocation commits. It sums the same
/// lengths [`ArrayMap::new`] and [`HashMap::new`] ask for — whatever slack the
/// allocator adds on top is not counted, which is the one respect in which this
/// under-reports.
fn footprint_bytes(attr: MapAttr) -> u64 {
    if attr.kind == MapKind::RingBuf {
        // A ring buffer's storage is frame-backed (`RingBuf::new` calls
        // `alloc_pages_on`), and the buddy allocator charges those frames to
        // the creating task's cgroup itself — data area plus the two control
        // pages. Charging again here would double-count, so the map layer takes
        // no separate footprint for a ring.
        return 0;
    }
    let cpus = cpu_width(attr.kind) as u64;
    let n = u64::from(attr.max_entries);
    let values = stride_for(attr.value_size) as u64 * cpus * n;
    if attr.kind.is_array() {
        values
    } else {
        let buckets = (attr.max_entries as usize).next_power_of_two() as u64;
        // keys + link + live + buckets, the four side arrays.
        values + u64::from(attr.key_size) * n + 4 * n + n + 4 * buckets
    }
}

/// A map behind an fd.
///
/// The anon-fd pattern `sys_eventfd` / `sys_memfd_create` use: an
/// `Arc<dyn FileOps>` with no backing file. `read`/`write` are `Unsupported` —
/// a map fd is a handle, not a stream, and Linux answers `read(2)` on one with
/// `EINVAL` as well.
///
/// Lives here rather than beside the `bpf(2)` handler because more than one
/// caller has to recover a map from a descriptor (element ops, and program load
/// resolving `LD_IMM64` map references), and a downcast only works where every
/// caller can name the concrete type.
#[derive(Debug)]
pub struct MapFile {
    map: Arc<BpfMap>,
}

impl MapFile {
    /// Wrap a created map for installation in an fd table.
    #[must_use]
    pub fn new(map: Arc<BpfMap>) -> Self {
        Self { map }
    }

    /// The map behind this fd.
    #[must_use]
    pub fn map(&self) -> Arc<BpfMap> {
        Arc::clone(&self.map)
    }
}

impl narf_filesystem::FileOps for MapFile {
    fn read<'a>(
        &'a self,
        _offset: u64,
        _buf: &'a mut [u8],
    ) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Err(narf_filesystem::FsError::Unsupported) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Err(narf_filesystem::FsError::Unsupported) })
    }
    fn stat(&self) -> narf_filesystem::Stat {
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }

    /// `mmap(2)` a ring buffer's shared pages — the zero-copy consumer surface.
    ///
    /// The frame list [`crate::ringbuf::RingBuf::mmap_frames`] returns is the
    /// consumer page, the producer page, then the data pages, in order. Both
    /// `offset` and `len` are page-aligned by the syscall layer, so this maps
    /// any aligned sub-range of that list — a consumer typically maps the
    /// consumer page writable and the producer-plus-data range read-only in two
    /// calls, the layout libbpf's `ring_buffer__new` expects. A non-ring map fd
    /// has no `mmap` backing, matching Linux (`ENODEV` on a keyed map).
    fn mmap_frames(
        &self,
        offset: u64,
        len: usize,
    ) -> Result<alloc::vec::Vec<u64>, narf_filesystem::FsError> {
        let rb = self
            .map
            .ringbuf()
            .ok_or(narf_filesystem::FsError::Unsupported)?;
        let all = rb.mmap_frames();
        let page = RINGBUF_PAGE as usize;
        let total = all.len() * page;
        let off = offset as usize;
        // The syscall layer aligns both, but the range must still land inside
        // the ring's pages.
        if off % page != 0 || len % page != 0 || len == 0 || off >= total || off + len > total {
            return Err(narf_filesystem::FsError::InvalidData);
        }
        let start = off / page;
        Ok(all[start..start + len / page].to_vec())
    }

    /// `poll(2)` readiness: readable exactly when the ring holds an unconsumed
    /// record. A keyed map fd is never readable this way.
    fn poll_readiness(&self) -> u32 {
        match self.map.ringbuf() {
            Some(rb) if rb.available_data() > 0 => narf_filesystem::POLL_IN,
            _ => 0,
        }
    }

    /// A ring buffer's [`crate::ringbuf::RingBuf::output`] fires a readiness
    /// `notify` on publish, so a parked `poll`/`epoll` waiter wakes promptly
    /// rather than only on the fallback re-scan.
    fn readiness_notifies(&self) -> bool {
        self.map.ringbuf().is_some()
    }

    /// The hook every fd-to-map recovery goes through.
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

// ── the program-facing kfuncs ───────────────────────────────────────

/// Largest key a map kfunc can carry.
///
/// The key travels as a `u64` scalar rather than as a byte region, so a program
/// writes `narf_map_lookup(map, 7, ...)` instead of spilling a key to its stack
/// and passing a pointer/length pair. The kfunc reads the low `key_size` bytes
/// little-endian, which is exactly the layout `u32`-keyed and `u64`-keyed maps
/// have.
///
/// // LINUX-GAP: a map whose `key_size` exceeds 8 is syscall-only. Linux's
/// `bpf_map_lookup_elem` helper takes a pointer, so a wide key is no different
/// there. Supporting one here needs a second kfunc taking `&[u8]`, and that
/// spends two of the five argument registers on the key — leaving no room for
/// both a sized output region and a flag word. The scalar form covers the map
/// shapes programs actually use; the wide-key form can be added when something
/// needs it.
pub const KFUNC_MAX_KEY_SIZE: u32 = 8;

/// Error returned by a map kfunc, as a negative errno in R0.
///
/// A kfunc reports failure through its return value rather than trapping: a trap
/// would make every map access a potential program-termination point, and the
/// verifier's job correspondingly harder. The same rule
/// `crate::kfuncs::narf_counter_add` follows.
fn kfunc_err(e: MapError) -> i64 {
    -(i64::from(e.errno()))
}

/// Recover the map a `Trusted<BpfMap>` names.
///
/// # Safety
///
/// The verifier proved the register holds a map handle at offset zero — that is
/// `check_args`' `p.off.as_const() != Some(0)` rejection for every non-`Mem`
/// pointer argument, and the reason `crate::provisional` refuses map forms
/// outright. The pointee is kept alive by the `Arc` the program holds for its
/// whole life (`BpfProg::maps`), so the borrow cannot outlive it.
unsafe fn map_of(handle: &crate::types::Trusted<BpfMap>) -> &BpfMap {
    // SAFETY: forwarded from this function's own contract.
    unsafe { &*handle.as_ptr() }
}

/// Write a `u64` key into a `key_size`-wide buffer.
///
/// `None` when the map's key is wider than a scalar can carry.
fn scalar_key(
    map: &BpfMap,
    key: u64,
    buf: &mut [u8; KFUNC_MAX_KEY_SIZE as usize],
) -> Option<usize> {
    let n = map.attr().key_size;
    if n > KFUNC_MAX_KEY_SIZE {
        return None;
    }
    let bytes = key.to_le_bytes();
    let n = n as usize;
    buf[..n].copy_from_slice(&bytes[..n]);
    Some(n)
}

crate::kfunc! {
    /// Copy the calling CPU's value for `key` into `out`.
    ///
    /// Returns `0`, or a negative errno: `-ENOENT` for a missing key, `-EINVAL`
    /// for a wrong-width `out` or a key wider than [`KFUNC_MAX_KEY_SIZE`].
    ///
    /// // LINUX-GAP: Linux's `bpf_map_lookup_elem` returns a *pointer into the
    /// map value* that the program then reads and writes directly. This copies
    /// instead, for three reasons that all point the same way: the interpreter
    /// has no synthetic region that could alias a map's value bytes, so a
    /// borrowed pointer would be unrunnable there; a borrowed pointer outlives
    /// the lookup, so keeping it valid needs the per-element RCU lifetime Linux
    /// pays for (`bpf_map_free_deferred`, `PTR_TO_MAP_VALUE_OR_NULL`, and the
    /// whole `map_value` invalidation machinery); and a copy makes a per-CPU
    /// read atomic with respect to a concurrent update, which a borrowed
    /// pointer does not. The cost is one memcpy of `value_size` bytes.
    ///
    /// `_out_len` is never read. It exists because `&mut [u8]` is
    /// `ArgFlags::SIZED_BY_NEXT`: the verifier bounds the region against the
    /// *following* argument register, and `<&mut [u8]>::from_raw` builds the
    /// slice from that same register — so `out.len()` already is `_out_len` and
    /// comparing them would prove nothing. The width that matters is checked
    /// where the authority is: `lookup_local` rejects any `out` that is not
    /// exactly `value_size` bytes.
    #[context(Atomic)]
    pub fn narf_map_lookup(map: crate::types::Trusted<BpfMap>, key: u64, out: &mut [u8], _out_len: u64) -> i64 {
        // SAFETY: see `map_of`.
        let map = unsafe { map_of(&map) };
        let mut kbuf = [0u8; KFUNC_MAX_KEY_SIZE as usize];
        let Some(n) = scalar_key(map, key, &mut kbuf) else {
            return kfunc_err(MapError::Invalid);
        };
        match map.ops().lookup_local(&kbuf[..n], out) {
            Ok(()) => 0,
            Err(e) => kfunc_err(e),
        }
    }

    /// Install the calling CPU's value for `key`.
    ///
    /// Returns `0`, or a negative errno. `flags` is the `BPF_ANY` /
    /// `BPF_NOEXIST` / `BPF_EXIST` word, with the same meanings the syscall
    /// gives it.
    ///
    /// `_value_len` is never read; see [`narf_map_lookup`].
    #[context(Atomic)]
    pub fn narf_map_update(map: crate::types::Trusted<BpfMap>, key: u64, value: &[u8], _value_len: u64, flags: u64) -> i64 {
        // SAFETY: see `map_of`.
        let map = unsafe { map_of(&map) };
        let mut kbuf = [0u8; KFUNC_MAX_KEY_SIZE as usize];
        let Some(n) = scalar_key(map, key, &mut kbuf) else {
            return kfunc_err(MapError::Invalid);
        };
        match map.ops().update_local(&kbuf[..n], value, flags) {
            Ok(()) => 0,
            Err(e) => kfunc_err(e),
        }
    }

    /// Remove `key`.
    ///
    /// Returns `0`, `-ENOENT` if absent, or `-EINVAL` for an array kind, which
    /// has no removable slots.
    #[context(Atomic)]
    pub fn narf_map_delete(map: crate::types::Trusted<BpfMap>, key: u64) -> i64 {
        // SAFETY: see `map_of`.
        let map = unsafe { map_of(&map) };
        let mut kbuf = [0u8; KFUNC_MAX_KEY_SIZE as usize];
        let Some(n) = scalar_key(map, key, &mut kbuf) else {
            return kfunc_err(MapError::Invalid);
        };
        match map.ops().delete(&kbuf[..n]) {
            Ok(()) => 0,
            Err(e) => kfunc_err(e),
        }
    }
}

// ── acquire / release ───────────────────────────────────────────────

crate::kfunc! {
    /// Take a reference to `map` that outlives the current non-preemptible
    /// region.
    ///
    /// This is the acquiring half of NARF's reference story, and the whole of
    /// its declaration is the signature. `Owned<T>` in *return* position is
    /// Linux's `KF_ACQUIRE`; `Option<_>` is `KF_RET_NULL`. There is no flag
    /// here to forget and no BTF parameter-name suffix to misspell —
    /// `kfunc!` writes down `<Option<Owned<BpfMap>> as BpfType>::DESC` and the
    /// verifier reads that same descriptor back out of the registry.
    ///
    /// `None` when the map already has [`MAX_BPF_PINS`] BPF references out;
    /// see there for why the cap is what makes the `Option` mean something.
    ///
    /// ## Why the matching release can never free
    ///
    /// `bpf/specification/spec.md` §4.6 forbids the global allocator on the
    /// program-run path, and dropping the *last* `Arc<BpfMap>` would call it.
    /// It cannot be the last one here. The only pointer the verifier admits
    /// for this parameter is `LD_IMM64`'s map pseudo-form, which it resolves
    /// against `Program::maps` and the interpreter resolves against
    /// `BpfProg::maps` — a strong `Arc` the program holds for its whole life,
    /// not merely for this run. So whenever a program can reach either half of
    /// the pair, at least one other strong reference is live, and both halves
    /// are a bare `fetch_add`/`fetch_sub` with no deallocation reachable.
    ///
    /// That argument is a property of *which pointers the verifier lets in*,
    /// so it is stated here rather than assumed: a future kfunc that acquired
    /// a map from, say, its id would not inherit it, and would need a deferred
    /// free instead.
    ///
    /// // LINUX-GAP: Linux has no `bpf_map_acquire` kfunc — a program's maps
    /// are pinned by the program and a BPF-visible refcount on one has no use
    /// there. The pair exists here because the reference *rules* need a
    /// production caller: before it, `ValidityDomain::Owned`,
    /// `ArgDesc::consumes_in_arg_position`, `AbsState::refs` and
    /// `VerifyError::LeakedReference` were exercised only against descriptors
    /// hand-written in the verifier's own tests, and nothing proved the
    /// `kfunc!` macro derived the same shape from a real signature.
    #[context(Atomic)]
    pub fn narf_map_acquire(map: crate::types::Trusted<BpfMap>) -> Option<crate::types::Owned<BpfMap>> {
        let ptr = map.as_ptr();
        // SAFETY: as `map_of` — the verifier proved this register holds a map
        // handle at offset zero, and `BpfProg::maps` keeps the pointee alive
        // for the whole run.
        if !unsafe { &*ptr }.pin() {
            return None;
        }
        // SAFETY: `ptr` is `Arc::as_ptr` of a live `Arc<BpfMap>` (same
        // argument), which is the pointer `Arc::into_raw` would have produced,
        // and the strong count is at least one for the duration.
        unsafe { Arc::increment_strong_count(ptr.cast_const()) };
        // SAFETY: the increment above is precisely the reference this handle
        // carries, and it has not been given to anyone else.
        Some(unsafe { crate::types::Owned::from_owned_ptr(ptr) })
    }

    /// Give back a reference [`narf_map_acquire`] took.
    ///
    /// The body drops the handle and does nothing else, and that is the point
    /// rather than an omission: `Owned<T>` is linear on the kernel side, so
    /// *consuming* it is what releases. A release kfunc whose author forgot
    /// the refcount would still be correct, and a kfunc that took an
    /// `Owned<T>` without meaning to release one could not be written — which
    /// is exactly what the verifier assumes when `consumes_in_arg_position()`
    /// strikes the reference off at this call site.
    #[context(Atomic)]
    pub fn narf_map_release(map: crate::types::Owned<BpfMap>) -> () {
        drop(map);
    }
}

// ── ring buffer ─────────────────────────────────────────────────────

/// `bpf_ringbuf_output` wakeup-control flags. There is no consumer to wake
/// yet, so both are accepted and ignored; any other bit is rejected.
const RB_NO_WAKEUP: u64 = 1 << 0;
const RB_FORCE_WAKEUP: u64 = 1 << 1;

/// `bpf_ringbuf_query` selectors: which statistic to read.
const RB_AVAIL_DATA: u64 = 0;
const RB_RING_SIZE: u64 = 1;
const RB_CONS_POS: u64 = 2;
const RB_PROD_POS: u64 = 3;

/// `-EINVAL` / `-EAGAIN` as a kfunc `i64` return.
const RB_EINVAL: i64 = -22;
const RB_EAGAIN: i64 = -11;

crate::kfunc! {
    /// Append `data` as one record to the ring buffer `map`, atomically — the
    /// `bpf_ringbuf_output` shape.
    ///
    /// Reserve, copy, and commit in one call: the program passes a buffer it
    /// already holds (its stack, a map value) rather than being handed a
    /// reserved region to fill, so there is no reference to track. Returns `0`,
    /// `-EINVAL` for an unknown `flags` bit or a `map` that is not a ring
    /// buffer, or `-EAGAIN` if the record does not fit — too large for the ring,
    /// or the ring is full right now.
    ///
    /// `_data_len` is never read; it is the scalar length that bounds `data`,
    /// and `data.len()` already is it (see [`narf_map_lookup`]).
    #[context(Atomic)]
    pub fn narf_ringbuf_output(map: crate::types::Trusted<BpfMap>, data: &[u8], _data_len: u64, flags: u64) -> i64 {
        // Only the two wakeup-control flags are defined. They are accepted and
        // ignored (nothing to wake yet); any other bit is a caller error.
        if flags & !(RB_NO_WAKEUP | RB_FORCE_WAKEUP) != 0 {
            return RB_EINVAL;
        }
        // SAFETY: see `map_of`.
        let map = unsafe { map_of(&map) };
        let Some(rb) = map.ringbuf() else {
            return RB_EINVAL;
        };
        match rb.output(data) {
            Ok(()) => 0,
            // Both "too big for the ring" and "full right now" surface as
            // `-EAGAIN`, exactly as Linux's `bpf_ringbuf_output` does.
            Err(_) => RB_EAGAIN,
        }
    }

    /// Read a statistic of the ring buffer `map` — the `bpf_ringbuf_query`
    /// shape.
    ///
    /// `flags` selects: `0` bytes available to consume, `1` ring size, `2`
    /// consumer position, `3` producer position. An unknown selector, or a
    /// `map` that is not a ring buffer, reads as `0`, as Linux's does.
    #[context(Atomic)]
    pub fn narf_ringbuf_query(map: crate::types::Trusted<BpfMap>, flags: u64) -> u64 {
        // SAFETY: see `map_of`.
        let map = unsafe { map_of(&map) };
        let Some(rb) = map.ringbuf() else {
            return 0;
        };
        match flags {
            RB_AVAIL_DATA => rb.available_data(),
            RB_RING_SIZE => rb.ring_size(),
            RB_CONS_POS => rb.consumer_pos(),
            RB_PROD_POS => rb.producer_pos(),
            _ => 0,
        }
    }
}
