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
    /// Sum of return values. Until maps land in Phase 3 this is how an
    /// attached program's effect is observed; the kfunc scratch counters in
    /// `crate::kfuncs` are the other way.
    accumulated: AtomicU64,
    /// Invocations that ended in a [`crate::interp::Trap`].
    traps: AtomicU64,
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
}

impl BpfProg {
    /// Verify and load.
    ///
    /// # Errors
    ///
    /// See [`LoadError`].
    pub fn load(cap: &Cap<BpfProgLoad, Grant>, req: LoadRequest) -> Result<Arc<Self>, LoadError> {
        cap.check_live()?;
        if req.insns.is_empty() || req.insns.len() > MAX_INSNS {
            return Err(LoadError::BadSize(req.insns.len()));
        }
        let registry = crate::kfunc::registry().ok_or(LoadError::NoRegistry)?;

        // Descriptors for every kfunc the program may call. The whole
        // registry, because NARF has one call ABI and one closed kfunc set —
        // there is no per-program-type helper allowlist to intersect with.
        let descs: Vec<_> = registry.all().iter().map(|e| e.desc()).collect();
        let prog = narf_bpf_verifier::Program {
            insns: &req.insns,
            context: req.context,
            // The probe ABI's `[u64; 4]` is already the ctx tuple, so there is
            // no ctx-rewriting layer and nothing to describe beyond four
            // scalars.
            ctx_fields: &CTX_SCALARS,
            kfuncs: &descs,
        };

        let mut subprogs: Vec<SubprogInfo> = Vec::new();
        let stack_bytes = match narf_bpf_verifier::verify(&prog) {
            Ok(v) => {
                if v.max_stack_bytes > MAX_STACK_BYTES {
                    return Err(LoadError::StackTooDeep {
                        needed: v.max_stack_bytes,
                        limit: MAX_STACK_BYTES,
                    });
                }
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
            runs: AtomicU64::new(0),
            accumulated: AtomicU64::new(0),
            traps: AtomicU64::new(0),
        }))
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
        let mut vm = Vm::new(
            crate::interp::VmProgram {
                insns: &self.insns,
                subprogs: &self.subprogs,
                context: self.context,
                fuel: self.initial_fuel,
            },
            ctx,
            ctx_len,
            frame,
            registry,
        );
        // An atomic program cannot reach an await point, so the future
        // completes on its first poll and `drive` never spins.
        let outcome = crate::interp::drive(vm.run());
        self.record(outcome);
        Some(outcome)
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
            },
            ctx,
            ctx_len,
            frame,
            registry,
        );
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

/// The four scalar fields of the probe context tuple.
static CTX_SCALARS: [narf_bpf_verifier::ArgDesc; MAX_CTX_WORDS] =
    [narf_bpf_verifier::ArgDesc::SCALAR64; MAX_CTX_WORDS];
