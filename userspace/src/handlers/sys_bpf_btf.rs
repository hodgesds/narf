//! `bpf(2)`'s `BPF_BTF_LOAD` (18).
//!
//! A loader hands the kernel a BTF blob describing the types its programs use;
//! the kernel validates it and returns an fd that other `bpf(2)` commands can
//! name. libbpf builds one for every object file it opens and loads it before
//! the first program, so a kernel that refuses `BPF_BTF_LOAD` refuses libbpf.
//!
//! NARF's own kfunc ABI does **not** use BTF — semantics come from Rust types
//! through the `kfunc!` macro and a link-section registry
//! (`bpf/specification/spec.md` §1.3). So this is a compatibility surface, and
//! the parsed graph deliberately has no consumer inside the kernel yet. That
//! is not a gap to be closed: wiring BTF into the verifier would reintroduce
//! exactly the drift the Rust-derived descriptors exist to prevent.
//!
//! The parsing lives in `narf-bpf-btf`, which is `#![forbid(unsafe_code)]`,
//! dependency-free, and host-tested — because the blob is a syscall argument
//! and a panic in the parser is a kernel panic driven by userspace. This file
//! is only the syscall glue: copy in, parse, wrap in an fd, report the reason
//! through `btf_log_buf`.
//!
//! ## Ids
//!
//! A loaded blob also gets a boot-unique `u32` id and an entry in an
//! [`narf_bpf::idreg::IdRegistry`], which is what `BPF_BTF_GET_NEXT_ID` walks
//! and `BPF_BTF_GET_FD_BY_ID` resolves (both live in `sys_bpf_info.rs`, with
//! the rest of the id family). The table is *here* rather than beside
//! `idreg::progs()`/`maps()` for one reason: `narf-bpf` does not depend on
//! `narf-bpf-btf` and must not start to — the parser is deliberately a leaf
//! crate with no kernel dependencies, and `narf-bpf` is what the interpreter
//! and the attach adapters live in. The registry is generic precisely so a
//! table can sit next to its object; only the `IdRegistry` type is borrowed.

#[allow(unused_imports)]
use super::*;

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use alloc::sync::Arc;
use narf_bpf::idreg::IdRegistry;
use narf_bpf_btf::{Btf, BtfError, Errno};

const E2BIG: i64 = 7;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
/// `EOPNOTSUPP`, which on Linux equals `ENOTSUP`.
const ENOTSUP: i64 = 95;

/// Same cap as `sys_bpf::read_attr`. Spelled here rather than reaching into
/// the sibling module so that the two files can be edited independently —
/// three agents share `sys_bpf.rs` and its private helpers are not an
/// interface.
const ATTR_BUF: usize = 256;

// `struct { … } btf` field offsets within `union bpf_attr`. It is the
// anonymous struct at offset 0, so these are absolute.
const BTF_DATA: usize = 0;
const BTF_LOG_BUF: usize = 8;
const BTF_SIZE: usize = 16;
const BTF_LOG_SIZE: usize = 20;
const BTF_LOG_LEVEL: usize = 24;
const BTF_LOG_TRUE_SIZE: usize = 28;
const BTF_FLAGS: usize = 32;

/// `BPF_LOG_LEVEL1 | BPF_LOG_LEVEL2 | BPF_LOG_STATS | BPF_LOG_FIXED`.
const BPF_LOG_MASK: u32 = 15;

/// How many parsed BTF blobs are currently alive.
///
/// Exists so that "closing the fd frees the blob" is a testable claim rather
/// than an assertion in a comment. It counts **blobs, not fds**: the counter
/// lives on [`BtfBlob`], so two fds naming one blob (which is exactly what
/// `BPF_BTF_GET_FD_BY_ID` produces) count once, and the number only falls when
/// the allocation is actually freed. Counting fds would have made this smoke
/// go green on a leak the moment a second handle existed.
static LIVE_BTF: AtomicUsize = AtomicUsize::new(0);

/// The number of loaded BTF blobs still alive.
#[must_use]
pub(crate) fn live_btf_count() -> usize {
    LIVE_BTF.load(Ordering::Relaxed)
}

/// Boot-lifetime and never handed back, as for programs, maps and links: a
/// reused id is how a loader that cached one silently starts naming a different
/// blob. 1, because `bpf_prog_info.btf_id == 0` means "no BTF".
static NEXT_BTF_ID: AtomicU32 = AtomicU32::new(1);

static BTF_IDS: IdRegistry<BtfBlob> = IdRegistry::new();

/// The BTF id table. See the module header for why it lives here.
#[must_use]
pub(crate) fn btf_ids() -> &'static IdRegistry<BtfBlob> {
    &BTF_IDS
}

/// A loaded blob and its id.
///
/// The id has to live on the *object* rather than on the fd, because the
/// registry's pruning half runs from `Drop` and there is exactly one drop that
/// means "this blob is gone". A `BtfFile` is a handle; several may name one
/// `BtfBlob`.
pub(crate) struct BtfBlob {
    id: u32,
    btf: Arc<Btf>,
}

impl BtfBlob {
    /// The blob's id, as `BPF_BTF_GET_FD_BY_ID` takes and `bpf_btf_info.id`
    /// reports.
    #[must_use]
    pub(crate) fn id(&self) -> u32 {
        self.id
    }

    /// The parsed blob.
    #[must_use]
    pub(crate) fn btf(&self) -> &Arc<Btf> {
        &self.btf
    }
}

impl Drop for BtfBlob {
    fn drop(&mut self) {
        LIVE_BTF.fetch_sub(1, Ordering::Relaxed);
        // The registry's anti-leak half. `IdRegistry::remove` never
        // materialises an `Arc<BtfBlob>` under its lock, so calling it from a
        // `Drop` cannot re-enter this function.
        BTF_IDS.remove(self.id);
    }
}

impl core::fmt::Debug for BtfBlob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BtfBlob")
            .field("id", &self.id)
            .field("nr_types", &self.btf.nr_types())
            .finish()
    }
}

/// The fd a successful `BPF_BTF_LOAD` returns.
///
/// Holds a reference to the blob and nothing else. `as_any` is the hook
/// `BPF_OBJ_GET_INFO_BY_FD` recovers it through — the same shape `ProgFile` and
/// `MapFile` use.
pub(crate) struct BtfFile {
    blob: Arc<BtfBlob>,
}

impl BtfFile {
    /// Parse-and-register: assigns the id, records it, and returns the first
    /// handle. The registry holds a `Weak`, so the entry is made from the `Arc`
    /// that is about to be handed out rather than before it exists.
    fn load(btf: Btf) -> Self {
        LIVE_BTF.fetch_add(1, Ordering::Relaxed);
        let id = NEXT_BTF_ID.fetch_add(1, Ordering::Relaxed);
        let blob = Arc::new(BtfBlob {
            id,
            btf: Arc::new(btf),
        });
        BTF_IDS.insert(id, &blob);
        Self { blob }
    }

    /// A second handle on an already-registered blob, for
    /// `BPF_BTF_GET_FD_BY_ID`. Its own `Arc`, so it keeps the blob alive
    /// independently of the fd that loaded it.
    #[must_use]
    pub(crate) fn from_blob(blob: Arc<BtfBlob>) -> Self {
        Self { blob }
    }

    /// The blob behind this fd.
    #[must_use]
    pub(crate) fn btf(&self) -> Arc<Btf> {
        Arc::clone(self.blob.btf())
    }

    /// The blob's id.
    #[must_use]
    pub(crate) fn id(&self) -> u32 {
        self.blob.id()
    }
}

impl core::fmt::Debug for BtfFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BtfFile")
            .field("id", &self.blob.id)
            .field("nr_types", &self.blob.btf.nr_types())
            .finish()
    }
}

impl narf_filesystem::FileOps for BtfFile {
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
        // Size 0, like Linux's anon-inode bpf fds — the blob is reachable
        // through `bpf(2)`, not through `read(2)`, and reporting its length
        // here would invite a loader to try the latter.
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// Where a validation message goes, and whether one was asked for.
struct LogTarget {
    ubuf: u64,
    size: u32,
    /// The caller's `size` argument, so the write-back of `btf_log_true_size`
    /// only happens if that field is inside what they passed.
    attr_uptr: u64,
    attr_size: usize,
    wanted: bool,
}

impl LogTarget {
    /// Validate the three log fields together.
    ///
    /// Mirrors Linux's `bpf_verifier_log_attr_valid`: a buffer without a level
    /// is a buffer nothing will ever be written to, and a level without a
    /// buffer is a request with nowhere to put the answer. Both are caller
    /// bugs, and Linux reports them rather than silently doing nothing.
    fn new(attr_uptr: u64, attr_size: usize, attr: &[u8; ATTR_BUF]) -> Result<Self, i64> {
        let ubuf = u64_at(attr, BTF_LOG_BUF);
        let size = u32_at(attr, BTF_LOG_SIZE);
        let level = u32_at(attr, BTF_LOG_LEVEL);

        if (ubuf != 0) != (size != 0) {
            return Err(-EINVAL);
        }
        if ubuf != 0 && level == 0 {
            return Err(-EINVAL);
        }
        if level & !BPF_LOG_MASK != 0 {
            return Err(-EINVAL);
        }
        if size > u32::MAX >> 2 {
            return Err(-EINVAL);
        }
        Ok(Self {
            ubuf,
            size,
            attr_uptr,
            attr_size,
            wanted: ubuf != 0 && level != 0,
        })
    }

    /// Write `msg` (NUL-terminated, truncated to fit) into the caller's
    /// buffer, and report the length it would have needed.
    ///
    /// A failed write is ignored on purpose: the caller asked for diagnostics,
    /// not for the syscall's result to depend on their buffer being mapped.
    /// Linux does the same — `bpf_vlog_finalize`'s `copy_to_user` failure
    /// turns into `-EFAULT` only for the log, never for the verdict.
    fn emit(&self, msg: &str) {
        if !self.wanted {
            return;
        }
        let bytes = msg.as_bytes();
        // Including the terminator, which is what Linux's `btf_log_true_size`
        // documents ("including terminating zero").
        let true_size = bytes.len().saturating_add(1);

        let cap = self.size as usize;
        if cap > 0 {
            let keep = core::cmp::min(bytes.len(), cap - 1);
            let mut out = alloc::vec::Vec::with_capacity(keep + 1);
            out.extend_from_slice(&bytes[..keep]);
            out.push(0);
            // SAFETY: `copy_to_user` range-validates `ubuf..ubuf+out.len()`
            // and brackets SMAP, turning a bad pointer into `Err` rather than
            // a fault.
            let _ = unsafe { copy_to_user(self.ubuf, &out) };
        }

        // `btf_log_true_size` is an output field. Only write it if the caller
        // passed a `size` that covers it — a caller built against an older
        // `union bpf_attr` has something else at that offset.
        if self.attr_size >= BTF_LOG_TRUE_SIZE + 4 {
            if let Some(dst) = self.attr_uptr.checked_add(BTF_LOG_TRUE_SIZE as u64) {
                let v = u32::try_from(true_size).unwrap_or(u32::MAX);
                // SAFETY: as above; four bytes at a range-validated address.
                let _ = unsafe { copy_to_user(dst, &v.to_le_bytes()) };
            }
        }
    }
}

fn u32_at(buf: &[u8; ATTR_BUF], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn u64_at(buf: &[u8; ATTR_BUF], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Translate a parser rejection into an errno.
///
/// The parser deals in [`Errno`] — a three-variant enum — rather than numbers,
/// so that it stays host-testable with no kernel dependency. This is the only
/// place the mapping exists.
const fn errno_of(e: BtfError) -> i64 {
    match e.errno() {
        Errno::Invalid => -EINVAL,
        Errno::TooBig => -E2BIG,
        Errno::NotSupported => -ENOTSUP,
    }
}

/// `BPF_BTF_LOAD`.
///
/// The privilege gate is in `sys_bpf`, before dispatch, so an unprivileged
/// caller never reaches this function and never gets to influence a kernel
/// allocation with `btf_size`.
pub(crate) fn btf_load(attr_uptr: u64, size: usize) -> i64 {
    if attr_uptr == 0 || size == 0 || size > ATTR_BUF {
        return -EINVAL;
    }
    let mut attr = [0u8; ATTR_BUF];
    // SAFETY: caller-supplied pointer, range-validated inside
    // `copy_from_user`, which also opens and closes the SMAP window and turns
    // a fault into `Err(EFAULT)` rather than a kernel panic.
    if let Err(e) = unsafe { copy_from_user(&mut attr[..size], attr_uptr) } {
        return -(e as i64);
    }

    // `btf_size` lives at offset 16, so a caller who passed fewer than 20
    // bytes has not told us how big the blob is.
    if size < BTF_SIZE + 4 {
        return -EINVAL;
    }

    let log = match LogTarget::new(attr_uptr, size, &attr) {
        Ok(l) => l,
        Err(e) => return e,
    };

    // `btf_flags` is where `BPF_F_TOKEN_FD` lives on Linux. NARF has no BPF
    // token, and a flag we silently ignore is a permission check we silently
    // skip, so any nonzero value is refused. A caller who passed a `size`
    // stopping short of the field reads zero here, because `attr` is zeroed
    // before the copy — the same zero-extension Linux does.
    if u32_at(&attr, BTF_FLAGS) != 0 {
        return -EINVAL;
    }

    let btf_size = u32_at(&attr, BTF_SIZE) as usize;
    let btf_uptr = u64_at(&attr, BTF_DATA);

    if btf_size == 0 {
        log.emit("btf: empty blob");
        return -EINVAL;
    }
    // Checked before the copy, so an absurd `btf_size` never reaches the
    // allocator. Same limit as Linux's `BTF_MAX_SIZE`.
    if btf_size > narf_bpf_btf::MAX_BTF_SIZE {
        log.emit("btf: blob exceeds the maximum BTF size");
        return -E2BIG;
    }
    if btf_uptr == 0 {
        return -EFAULT;
    }

    // SAFETY: `copy_from_user_vec` validates the range and the length bound
    // before it allocates.
    let data = match unsafe { copy_from_user_vec(btf_uptr, btf_size) } {
        Ok(d) => d,
        Err(e) => return -(e as i64),
    };

    let btf = match Btf::parse(data) {
        Ok(b) => b,
        Err(e) => {
            // `[type_id] reason`, the shape Linux's verifier log uses, so a
            // human reading a libbpf failure sees something familiar. The type
            // id is 0 for header- and section-level rejections.
            log.emit(&alloc::format!("btf: [{}] {}", e.type_id(), e.message()));
            return errno_of(e);
        }
    };

    log.emit(&alloc::format!(
        "btf: ok, {} types, {} bytes of strings",
        btf.nr_types(),
        btf.header().str_len
    ));

    let ops: Arc<dyn narf_filesystem::FileOps> = Arc::new(BtfFile::load(btf));
    let task = current_task_id();
    match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops,
            offset: 0,
            // Linux sets close-on-exec on every bpf fd
            // (`bpf_btf_new_fd` passes `O_RDONLY | O_CLOEXEC`), because a
            // leaked one is a leaked capability.
            flags: crate::fd::FD_CLOEXEC,
            status_flags: 0,
        })
    }) {
        Some(n) => n as i64,
        None => -EMFILE,
    }
}
