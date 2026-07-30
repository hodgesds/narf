//! The program object and its lifecycle.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use narf_bpf_isa::Insn;
use narf_bpf_verifier::kfunc::Context;
use narf_bpf_verifier::SubprogInfo;
use narf_bpf_verifier::{VerifyError, DEFAULT_FUEL, MAX_STACK_BYTES};
use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};

use crate::interp::{Outcome, Vm, MAX_CTX_WORDS};
use crate::mem::{BpfStack, HeapStack, PerCpuRegion, PerCpuStackStub, STUB_STACK_BYTES};

/// Authority to load and verify a BPF program.
///
/// `bpf/specification/spec.md` §4.10: there is no unprivileged mode and no
/// second set of limits. Linux forks its whole verifier on `allow_ptr_leaks`,
/// `allow_uninit_stack`, `bpf_capable`, and `bypass_spec_v1/v4` — and then
/// every distribution disables unprivileged BPF anyway.
#[derive(Copy, Clone, Debug)]
pub struct BpfProgLoad;
impl CapType for BpfProgLoad {
    const KIND: CapKind = CapKind::BpfProgLoad;
}

/// Authority to attach a verified program to a hook.
#[derive(Copy, Clone, Debug)]
pub struct BpfAttach;
impl CapType for BpfAttach {
    const KIND: CapKind = CapKind::BpfAttach;
}

/// Largest program the loader accepts, in instruction slots.
///
/// Not a verification limit — fuel handles termination, so there is no
/// `BPF_COMPLEXITY_LIMIT_INSNS` here. This is a memory bound on the copy from
/// userspace, nothing more.
pub const MAX_INSNS: usize = 1 << 16;

/// Why loading failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// The `Cap<BpfProgLoad, Grant>` was revoked.
    AuthorityRevoked,
    /// The kfunc registry has not been built yet — `register_initcalls()` has
    /// not run.
    NoRegistry,
    /// Empty program, or more than [`MAX_INSNS`] slots.
    BadSize(usize),
    /// The verifier rejected it.
    Rejected(VerifyError),
    /// The program needs more stack than the current provider offers.
    StackTooDeep { needed: u32, limit: u32 },
}

impl From<CapError> for LoadError {
    fn from(_: CapError) -> Self {
        LoadError::AuthorityRevoked
    }
}

/// A loaded, verified program.
///
/// Reference-counted (`Arc`) rather than owned by its fd, because a program
/// outlives the fd once it is attached — the same lifetime shape as
/// `Arc<Task>` elsewhere in the tree.
#[derive(Debug)]
pub struct BpfProg {
    /// Program name, as supplied at load.
    pub name: String,
    /// Kernel-wide id.
    pub id: u32,
    /// The validated instruction image. Verification does not rewrite
    /// instructions — lowering happens once, in the JIT (spec §1.7).
    insns: Vec<Insn>,
    /// The execution context this program was verified for.
    context: Context,
    /// Starting fuel for each invocation.
    initial_fuel: u64,
    /// Bytes of BPF stack the program may use.
    stack_bytes: u32,
    /// Per-subprogram frame sizes, as the verifier modelled them.
    ///
    /// Kept, not discarded: `Ok` from the verifier is conditional on the
    /// frames being laid out this way. Handing every frame a fixed width
    /// instead disagreed in both directions — eight tiny subprograms verified
    /// with a 64-byte budget and then exhausted the region on the first call,
    /// and a single 1 KiB callee verified and then wrote below it.
    subprogs: Vec<SubprogInfo>,
    /// Invocations.
    runs: AtomicU64,
    /// Sum of return values. One of three ways an attached program's effect is
    /// observed, alongside the scratch counters in `crate::kfuncs` and — now
    /// that they exist — the maps in `crate::map`.
    accumulated: AtomicU64,
    /// Invocations that ended in a [`crate::interp::Trap`].
    traps: AtomicU64,
    /// Native code, when the program passed every gate in
    /// [`crate::jit_glue`]. `None` means it runs interpreted, which is a
    /// complete implementation and not a degraded one.
    jit: Option<crate::jit_glue::JitImage>,
    /// The arenas this program may address, if any.
    ///
    /// Held as an `Arc` because the same arenas are reachable through an
    /// [`crate::arena::ArenaFile`] fd that userspace mapped, and the frames must
    /// outlive whichever of the two goes away first.
    ///
    /// Bound at load time and never after: the interpreter reads this slice on
    /// the run path with no lock, which is only sound because it cannot change
    /// under it.
    arenas: Option<Arc<crate::arena::ArenaGroup>>,
    /// The maps this program may reference, paired with the file descriptors
    /// its `LD_IMM64` immediates name.
    ///
    /// Held for the program's life, which is the point: the `Arc` is what keeps
    /// a map alive after the fd that created it is closed. Linux does the same
    /// through `prog->aux->used_maps`.
    maps: Vec<(i32, Arc<crate::map::BpfMap>)>,
}

static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// A load request.
#[derive(Debug)]
pub struct LoadRequest {
    /// Program name (Linux caps this at 16 bytes; so do we, at the syscall
    /// boundary).
    pub name: String,
    /// The instruction image.
    pub insns: Vec<Insn>,
    /// The execution context the target hook provides. Declared by the hook,
    /// never by a program flag — spec §4.5.
    pub context: Context,
    /// Every map the program may reference, in the order the loader supplied
    /// them, each paired with the file descriptor its `LD_IMM64` immediates
    /// name.
    ///
    /// Resolved by the caller, not here: `narf-bpf` cannot depend on
    /// `narf-userspace` (that is the cycle spec §3.1 forbids), so it has no way
    /// to turn an fd into a map. The `bpf(2)` handler does the lookup and hands
    /// over the `Arc`s, which is also what makes the program hold a reference
    /// for its whole life — a map cannot be freed out from under a program that
    /// names it.
    pub maps: Vec<(i32, Arc<crate::map::BpfMap>)>,
}

impl BpfProg {
    /// Verify and load.
    ///
    /// # Errors
    ///
    /// See [`LoadError`].
    pub fn load(cap: &Cap<BpfProgLoad, Grant>, req: LoadRequest) -> Result<Arc<Self>, LoadError> {
        Self::load_with_arena(cap, req, None)
    }

    /// Verify and load, binding an arena group the program may address.
    ///
    /// A separate entry point rather than a field on [`LoadRequest`]: that struct
    /// is built by literal in `narf-userspace`'s `bpf(2)` handler and in
    /// `crate::bench`, so a new field would be a breaking change across crates
    /// for the benefit of one caller.
    ///
    /// The group is *not* something the verifier is told about, and that is worth
    /// stating precisely. `narf-bpf-verifier` bounds an arena displacement
    /// against a fixed `ARENA_WINDOW_BYTES`, not against this group's extent, so
    /// it will accept a program that walks past the end of its own arenas. What
    /// makes that safe is the runtime: the interpreter resolves every handle
    /// against exactly this slice and traps
    /// [`crate::interp::Trap::ArenaOutOfBounds`] otherwise, and the slot's tail
    /// guard means even an unchecked access could not reach another program's
    /// arenas. It is also why `crate::jit_glue` still refuses arena programs —
    /// native code performs neither check.
    ///
    /// # Errors
    ///
    /// See [`LoadError`].
    pub fn load_with_arena(
        cap: &Cap<BpfProgLoad, Grant>,
        req: LoadRequest,
        arenas: Option<Arc<crate::arena::ArenaGroup>>,
    ) -> Result<Arc<Self>, LoadError> {
        cap.check_live()?;
        if req.insns.is_empty() || req.insns.len() > MAX_INSNS {
            return Err(LoadError::BadSize(req.insns.len()));
        }
        let registry = crate::kfunc::registry().ok_or(LoadError::NoRegistry)?;
        reject_unrunnable(&req.insns)?;

        // Descriptors for every kfunc the program may call. The whole
        // registry, because NARF has one call ABI and one closed kfunc set —
        // there is no per-program-type helper allowlist to intersect with.
        let descs: Vec<_> = registry.all().iter().map(|e| e.desc()).collect();
        // The verifier's view of the map set: an fd, and the three widths that
        // bound an access. Built here rather than by the caller so the
        // descriptor cannot disagree with the map it describes.
        let map_descs: Vec<narf_bpf_verifier::MapDesc> = req
            .maps
            .iter()
            .map(|(fd, m)| {
                let a = m.attr();
                narf_bpf_verifier::MapDesc {
                    fd: *fd,
                    key_size: a.key_size,
                    value_size: a.value_size,
                    max_entries: a.max_entries,
                }
            })
            .collect();
        let prog = narf_bpf_verifier::Program {
            insns: &req.insns,
            context: req.context,
            // The probe ABI's `[u64; 4]` is already the ctx tuple, so there is
            // no ctx-rewriting layer and nothing to describe beyond four
            // scalars.
            ctx_fields: &CTX_SCALARS,
            kfuncs: &descs,
            maps: &map_descs,
        };

        let mut subprogs: Vec<SubprogInfo> = Vec::new();
        // `None` unless a clean `verify()` produced a program that passed every
        // gate. Deliberately not set on the `provisional` path below: that
        // acceptance is *defined* as leaning on the interpreter's runtime
        // bounds checks, which native code does not perform.
        let mut jit = None;
        let stack_bytes = match narf_bpf_verifier::verify(&prog) {
            Ok(v) => {
                if v.max_stack_bytes > MAX_STACK_BYTES {
                    return Err(LoadError::StackTooDeep {
                        needed: v.max_stack_bytes,
                        limit: MAX_STACK_BYTES,
                    });
                }
                jit = crate::jit_glue::try_compile(&v, true).ok();
                subprogs = v.subprogs;
                v.max_stack_bytes.max(1)
            }
            // Phase 2 is not here yet: the abstract interpreter reports
            // `NotImplemented` for everything it decoded successfully. Fall
            // through to `provisional`, which is a *structural* check plus the
            // interpreter's runtime bounds checks — see that module for why
            // this is not fail-open.
            Err(VerifyError::NotImplemented(_)) => {
                crate::provisional::accept(&req.insns, req.context, registry)
                    .map_err(LoadError::Rejected)?;
                STUB_STACK_BYTES as u32
            }
            Err(e) => return Err(LoadError::Rejected(e)),
        };

        Ok(Arc::new(Self {
            name: req.name,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            insns: req.insns,
            context: req.context,
            initial_fuel: DEFAULT_FUEL,
            stack_bytes,
            subprogs,
            jit,
            arenas,
            maps: req.maps,
            runs: AtomicU64::new(0),
            accumulated: AtomicU64::new(0),
            traps: AtomicU64::new(0),
        }))
    }

    /// The arenas this program may address. Empty when it has none.
    #[inline]
    #[must_use]
    pub fn arenas(&self) -> &[Arc<crate::arena::ProgArena>] {
        self.arenas.as_ref().map_or(&[], |g| g.arenas())
    }

    /// The context this program was verified for.
    #[inline]
    #[must_use]
    pub const fn context(&self) -> Context {
        self.context
    }

    /// Instruction count.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    /// Whether the program is empty. Never true for a loaded program.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    /// The map named by this file descriptor, or `None`.
    ///
    /// What the interpreter resolves `LD_IMM64`'s `MapFd` form against. The
    /// verifier already proved the fd is in the set — this is the runtime
    /// looking up the same entry, and a `None` here would mean the two
    /// disagreed.
    #[must_use]
    pub fn map_by_fd(&self, fd: i32) -> Option<&Arc<crate::map::BpfMap>> {
        self.maps.iter().find(|(f, _)| *f == fd).map(|(_, m)| m)
    }

    /// The map at this position in the loader's fd array — `LD_IMM64`'s
    /// `MapIdx` form.
    #[must_use]
    pub fn map_by_idx(&self, idx: usize) -> Option<&Arc<crate::map::BpfMap>> {
        self.maps.get(idx).map(|(_, m)| m)
    }

    /// How many maps this program references.
    #[must_use]
    pub fn map_count(&self) -> usize {
        self.maps.len()
    }

    /// Invocation count.
    #[inline]
    #[must_use]
    pub fn runs(&self) -> u64 {
        self.runs.load(Ordering::Relaxed)
    }

    /// Sum of return values across every invocation.
    #[inline]
    #[must_use]
    pub fn accumulated(&self) -> u64 {
        self.accumulated.load(Ordering::Relaxed)
    }

    /// Invocations that trapped.
    #[inline]
    #[must_use]
    pub fn traps(&self) -> u64 {
        self.traps.load(Ordering::Relaxed)
    }

    /// Run the program in atomic context, on the per-CPU stack.
    ///
    /// Safe to call with IRQs masked and a caller lock held, which is exactly
    /// how `tracing::dispatch::fire()` invokes handlers: no allocation, no
    /// locks beyond the per-CPU stack claim, and no await point reachable
    /// (a sleepable kfunc from an atomic program is [`crate::interp::Trap`],
    /// not a park).
    ///
    /// Returns `None` if the per-CPU stack provider declined — nesting, or a
    /// stack request larger than a frame. Declining is the designed
    /// behaviour: `bpf/specification/spec.md` §1.5 makes re-entrancy a depth
    /// counter, so depth N+1 loses its invocation rather than corrupting the
    /// frame below it.
    pub fn run_atomic(&self, ctx: [u64; MAX_CTX_WORDS], ctx_len: usize) -> Option<Outcome> {
        // The arena test is the belt to `jit_glue`'s gate-2 brace. That gate
        // already means `jit` is `None` for any program the verifier saw touch an
        // arena, so this can only fire if the two ever disagree — and the failure
        // mode if they do is native code dereferencing a handle with no bound
        // whatsoever, which is worth one comparison per invocation to make
        // structurally impossible rather than merely currently true.
        if self.jit.is_some() && self.arenas().is_empty() {
            return self.run_atomic_native(ctx, ctx_len);
        }
        self.run_atomic_interpreted(ctx, ctx_len)
    }

    /// Run interpreted, whatever `self.jit` holds.
    ///
    /// Public so the differential smoke can compare the two paths on the same
    /// program. That comparison is the only test that checks the emitter's
    /// *semantics* rather than its bytes — golden encodings prove the emitter
    /// produced what was intended, and the interpreter is the oracle for
    /// whether the intent was right.
    pub fn run_atomic_interpreted(
        &self,
        ctx: [u64; MAX_CTX_WORDS],
        ctx_len: usize,
    ) -> Option<Outcome> {
        if self.context != Context::Atomic {
            return None;
        }
        // Prefer the real per-CPU region; fall back to the stub only before
        // `memory::bpf_stack::init` has run. The fallback is deliberately
        // small, so a program verified against the real ceiling is *declined*
        // rather than silently run on a frame smaller than it was proved to
        // need — the two sizes disagreeing silently is what the stub-only path
        // used to do (4 KiB stub against a 16 KiB verified ceiling).
        let frame = if crate::mem::region_ready() {
            PerCpuRegion.acquire(self.stack_bytes as usize)?
        } else {
            PerCpuStackStub.acquire(self.stack_bytes as usize)?
        };
        let registry = crate::kfunc::registry()?;
        // Four readable words, tail zero-filled — the same contract
        // `run_atomic_native` provides, because the verifier proved all four
        // readable and the two paths must not disagree. See the note there.
        let mut ctx = ctx;
        for w in ctx.iter_mut().skip(ctx_len.min(MAX_CTX_WORDS)) {
            *w = 0;
        }
        let mut vm = Vm::new(
            crate::interp::VmProgram {
                insns: &self.insns,
                subprogs: &self.subprogs,
                context: self.context,
                fuel: self.initial_fuel,
                maps: &self.maps,
            },
            ctx,
            MAX_CTX_WORDS,
            frame,
            registry,
        )
        .with_arenas(self.arenas());
        // An atomic program cannot reach an await point, so the future
        // completes on its first poll and `drive` never spins.
        let outcome = crate::interp::drive(vm.run());
        self.record(outcome);
        Some(outcome)
    }

    /// Run the compiled image.
    ///
    /// Only reachable when [`crate::jit_glue::try_compile`] accepted the
    /// program, which means: the verifier proved it (not the `provisional`
    /// path), it uses no arena, it has no faulting accesses, it contains no
    /// back-edge, and it dereferences only R10 and R1. Those five gates are why
    /// this can hand control to generated code without the interpreter's
    /// per-access bounds checks.
    fn run_atomic_native(&self, ctx: [u64; MAX_CTX_WORDS], ctx_len: usize) -> Option<Outcome> {
        if self.context != Context::Atomic {
            return None;
        }
        let image = self.jit.as_ref()?;
        let mut frame = if crate::mem::region_ready() {
            PerCpuRegion.acquire(self.stack_bytes as usize)?
        } else {
            PerCpuStackStub.acquire(self.stack_bytes as usize)?
        };
        // The frame is already zeroed by the provider, which native code relies
        // on exactly as the interpreter does: the verifier permits reading a
        // widened stack slot before any concrete write, so the bytes must not be
        // a previous program's.
        let top = frame.top_addr();
        let _ = frame.bytes_mut();
        // The verifier types every program's context as four scalars
        // (`CTX_SCALARS`), so it proves all four readable — but the interpreter
        // additionally bounds reads at the *runtime* `ctx_len`, while native
        // code emits no such check. A caller passing fewer words therefore got
        // `Trap::BadAccess` interpreted and a zero read JITed: same program,
        // different answer. Reachable through perf, whose `ctx_len` is
        // `raw.len() / 8` and can be zero.
        //
        // Resolved in favour of what was actually proved: the runtime supplies
        // four readable words, zero-filling the tail. A caller with less data
        // is not lying to the program — `ctx[0]`-style length fields remain the
        // authority on how much is meaningful, as the XDP summary already does.
        // Per-attach-point context typing is the real fix and is spec §8's
        // remaining ctx item; this makes the two execution paths agree in the
        // meantime, which is the property that cannot be allowed to differ.
        let mut ctx = ctx;
        for w in ctx.iter_mut().skip(ctx_len.min(MAX_CTX_WORDS)) {
            *w = 0;
        }
        let entry = image.entry();
        // SAFETY: `entry` points at sealed, executable text emitted for this
        // program, entered with the ABI its prologue expects — `top` is the
        // frame's highest address (R10) and `ctx.as_ptr()` a live `[u64; 4]`
        // (R1). `ctx` outlives the call; `frame` is held across it so the
        // memory R10 addresses stays leased. The five gates above are what make
        // the absence of runtime bounds checks sound.
        let packed = unsafe { entry(top, ctx.as_ptr() as u64, self.initial_fuel) };
        // SysV's rax:rdx pair: low half is R0, high half is the exhaustion
        // flag. Reported out of band because no in-band sentinel works — the
        // obvious one, u64::MAX, is exactly what `r0 = -1; exit` returns.
        let value = packed as u64;
        let exhausted = (packed >> 64) as u64 != 0;
        let outcome = if exhausted {
            // Matches the interpreter: exhaustion stops the program with a
            // diagnostic rather than a fault, and the return value is
            // meaningless (§4.9). `at` is not recoverable from native code
            // without a side table, so it names the entry.
            Outcome::Trapped(crate::interp::Trap::OutOfFuel { at: 0 })
        } else {
            Outcome::Returned(value)
        };
        self.record(outcome);
        Some(outcome)
    }

    /// Whether this program runs as native code.
    #[inline]
    #[must_use]
    pub fn is_jited(&self) -> bool {
        self.jit.is_some()
    }

    /// Run the program on a heap stack owned by the caller's future.
    ///
    /// The sleepable path (spec §4.8): a sleeping program cannot hold a
    /// per-CPU slot across a yield, because another task may run on that CPU.
    pub async fn run_sleepable(
        &self,
        ctx: [u64; MAX_CTX_WORDS],
        ctx_len: usize,
    ) -> Option<Outcome> {
        let stack = HeapStack::new(self.stack_bytes as usize);
        let frame = stack.acquire(self.stack_bytes as usize)?;
        let registry = crate::kfunc::registry()?;
        let mut vm = Vm::new(
            crate::interp::VmProgram {
                insns: &self.insns,
                subprogs: &self.subprogs,
                context: self.context,
                fuel: self.initial_fuel,
                maps: &self.maps,
            },
            ctx,
            ctx_len,
            frame,
            registry,
        )
        .with_arenas(self.arenas());
        let outcome = vm.run().await;
        self.record(outcome);
        Some(outcome)
    }

    fn record(&self, outcome: Outcome) {
        self.runs.fetch_add(1, Ordering::Relaxed);
        match outcome {
            Outcome::Returned(v) => {
                self.accumulated.fetch_add(v, Ordering::Relaxed);
            }
            Outcome::Trapped(_) => {
                self.traps.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Refuse a construct the verifier accepts but no backend can execute.
///
/// A program the verifier proves and the runtime then cannot run is a contract
/// break even though it is not a safety hole — the same one [`MAX_STACK_BYTES`]
/// and `MAX_CALL_DEPTH` exist to prevent, and it is much worse to discover at
/// fire time than at load. The verifier is a library and stays general; this is
/// the runtime stating its own limit.
///
/// Today that is exactly one construct: `LD_IMM64`'s map-*value* pseudo-forms.
/// The verifier resolves and bounds them, but neither the interpreter (which has
/// no synthetic region aliasing a map's value bytes) nor the x86_64 emitter
/// (which does not lower `LD_IMM64` at all) can produce the address.
fn reject_unrunnable(insns: &[Insn]) -> Result<(), LoadError> {
    use narf_bpf_isa::{Decoded, Imm64};
    let mut i = 0usize;
    while i < insns.len() {
        // An undecodable image is the verifier's error to report, with its own
        // instruction index; stopping here would pre-empt a better diagnostic.
        let Ok((d, width)) = narf_bpf_isa::decode(insns, i) else {
            return Ok(());
        };
        if let Decoded::LoadImm64 {
            value: Imm64::MapValue { .. } | Imm64::MapIdxValue { .. },
            ..
        } = d
        {
            return Err(LoadError::Rejected(VerifyError::NotImplemented(
                "LD_IMM64 map-value pseudo-form: no backend can produce the address",
            )));
        }
        i += width;
    }
    Ok(())
}

/// The four scalar fields of the probe context tuple.
static CTX_SCALARS: [narf_bpf_verifier::ArgDesc; MAX_CTX_WORDS] =
    [narf_bpf_verifier::ArgDesc::SCALAR64; MAX_CTX_WORDS];

/// A loaded program behind an fd.
///
/// Anon-fd pattern, as `sys_eventfd` / `sys_memfd_create` use: an
/// `Arc<dyn FileOps>` in an `FdEntry` with no backing file. Reads and writes are
/// `Unsupported` — a prog fd is a handle, not a stream, and `read(2)` on one
/// returns `-EINVAL` on Linux too.
///
/// Lives here rather than beside the `bpf(2)` handler because more than one
/// caller needs to recover a program from a file descriptor —
/// `BPF_PROG_TEST_RUN` and `PERF_EVENT_IOC_SET_BPF` — and a downcast only works
/// if every one of them can name the concrete type. When it was private to the
/// syscall module, perf had no way to express the downcast at all.
#[derive(Debug)]
pub struct ProgFile {
    prog: Arc<BpfProg>,
}

impl ProgFile {
    /// Wrap a loaded program for installation in an fd table.
    #[must_use]
    pub fn new(prog: Arc<BpfProg>) -> Self {
        Self { prog }
    }

    /// The program behind this fd.
    #[must_use]
    pub fn prog(&self) -> Arc<BpfProg> {
        Arc::clone(&self.prog)
    }
}

impl narf_filesystem::FileOps for ProgFile {
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
    /// The hook every fd-to-program recovery goes through.
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}
