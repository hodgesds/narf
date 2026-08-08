//! BPF iterators — `BPF_LINK_CREATE(BPF_TRACE_ITER)` and `BPF_ITER_CREATE`.
//!
//! A BPF iterator runs a program once per object in a target set and serves the
//! concatenated output through a read-only fd. Linux builds that on `seq_file`
//! and a `bpf_seq_write` helper that appends formatted text; NARF has no
//! seq_file (its procfs uses a whole-buffer-per-open model), so this takes the
//! same shape at a coarser grain:
//!
//! * `BPF_LINK_CREATE` with `attach_type = BPF_TRACE_ITER` binds a program to a
//!   target *kind* and returns an [`IterLinkFile`] fd. Unlike every other link
//!   this is not a hook attachment — it claims nothing and detaches nothing — so
//!   it is a plain fd rather than a [`narf_bpf::link::BpfLink`].
//! * `BPF_ITER_CREATE` turns that link fd into a readable [`IterFile`].
//! * Reading the iterator runs the program over the target set, and each run's
//!   **return value** is emitted as one little-endian `u64` record. That is the
//!   deliberate divergence: NARF has no `bpf_seq_write`, so a program's output
//!   *is* its return value, eight bytes per object.
//!   // LINUX-GAP: no `bpf_seq_write` / variable-length seq records.
//!
//! The target kind is named by a small integer in `link_create.target_fd`,
//! because Linux's `iter_info` is a BTF-based descriptor NARF cannot resolve.
//! // LINUX-GAP: no BTF `bpf_iter_link_info`.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_bpf::prog::BpfProg;
use narf_filesystem::{FileOps, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

/// Iterate every BPF map, by id. The program's context is `[map_id]`.
pub(crate) const ITER_KIND_MAP: u32 = 0;
/// Iterate every loaded BPF program, by id. Context is `[prog_id]`.
pub(crate) const ITER_KIND_PROG: u32 = 1;
/// One past the last valid kind, so the syscall boundary can reject the rest.
pub(crate) const ITER_KIND_COUNT: u32 = 2;

/// The fd `BPF_LINK_CREATE(BPF_TRACE_ITER)` hands back: a program bound to a
/// target kind, from which `BPF_ITER_CREATE` makes a readable iterator.
pub(crate) struct IterLinkFile {
    prog: Arc<BpfProg>,
    kind: u32,
}

impl IterLinkFile {
    pub(crate) fn new(prog: Arc<BpfProg>, kind: u32) -> Self {
        Self { prog, kind }
    }
}

impl FileOps for IterLinkFile {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // A link fd is not readable; the iterator fd from `ITER_CREATE` is.
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// The readable iterator fd from `BPF_ITER_CREATE`.
///
/// The content is generated once, on first read, and served from a cached
/// buffer at the caller's offset — the same whole-buffer model NARF's procfs
/// uses, which is what read/pread/partial reads all rest on.
pub(crate) struct IterFile {
    prog: Arc<BpfProg>,
    kind: u32,
    output: IrqSafeSpinLock<Option<Vec<u8>>>,
}

impl IterFile {
    fn new(prog: Arc<BpfProg>, kind: u32) -> Self {
        Self {
            prog,
            kind,
            output: IrqSafeSpinLock::new(None),
        }
    }

    /// Run the program over the target set, emitting each run's return value.
    ///
    /// Called with no lock held: `run_atomic` brackets its own IRQs-masked
    /// section, and holding a spin lock across it would be both a long hold and
    /// a lock ordering hazard.
    fn generate(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut emit = |id: u32| {
            let mut ctx = [0u64; narf_bpf::interp::MAX_CTX_WORDS];
            ctx[0] = u64::from(id);
            if let Some(outcome) = self.prog.run_atomic(ctx, 8) {
                out.extend_from_slice(&outcome.value().to_le_bytes());
            }
        };
        let mut id = 0u32;
        match self.kind {
            ITER_KIND_MAP => {
                while let Some(next) = narf_bpf::idreg::maps().next_id(id) {
                    emit(next);
                    id = next;
                }
            }
            ITER_KIND_PROG => {
                while let Some(next) = narf_bpf::idreg::progs().next_id(id) {
                    emit(next);
                    id = next;
                }
            }
            // No other kind reaches here: `iter_create` rejects them.
            _ => {}
        }
        out
    }
}

impl FileOps for IterFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            // Generate once. A racing first read may generate twice; the loser's
            // work is dropped, which is cheaper than holding the lock across a
            // program run.
            if self.output.lock().is_none() {
                let generated = self.generate();
                let mut slot = self.output.lock();
                if slot.is_none() {
                    *slot = Some(generated);
                }
            }
            let slot = self.output.lock();
            let bytes = slot.as_ref().expect("generated above");
            let start = (offset as usize).min(bytes.len());
            let n = (bytes.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&bytes[start..start + n]);
            Ok(n)
        })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// Build the iterator fd for `BPF_ITER_CREATE`, given the object behind the
/// caller's `link_fd`. `None` if that fd is not an iterator link.
pub(crate) fn iter_from_link(link_ops: &Arc<dyn FileOps>) -> Option<Arc<dyn FileOps>> {
    let link = link_ops.as_any()?.downcast_ref::<IterLinkFile>()?;
    Some(Arc::new(IterFile::new(Arc::clone(&link.prog), link.kind)))
}
