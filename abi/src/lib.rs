//! narf-abi — kernel↔user ABI surface.
//!
//! Spec: `abi/specification/spec.md` (Stage 3). This crate pins the wire
//! shapes of the submission / completion rings: the `Submission` and
//! `Completion` structs, the `OpCode` enumeration, `SubmissionFlags`
//! bitflags, the `NarfStatus` completion-status enum, and thin type
//! aliases over the Narf-Ring SPSC primitives from `narf-ipc`.
//!
//! Wave 2 scope — what lands here:
//!
//! - `#[repr(C)] Submission { op, flags, caps: [CapSlot; 4], tag, inline: [u64; 6] }`
//!   matching the spec's §3 sketch exactly. Layout is load-bearing —
//!   the `const _: () = assert!(size_of == 144)` pin (see the layout
//!   block above `Submission`) catches silent drift. The naive 128-byte
//!   sum undercounts two padding runs forced by `CapSlot`'s 16-align.
//! - `#[repr(C)] Completion { tag, status, result: [u64; 6] }`.
//! - `OpCode` (`#[repr(u32)]`) with explicit discriminants so wire tags
//!   are stable under reordering. Stage-3 Wave-2 enumerates enough
//!   variants to exercise the ring round-trip; more land as subsystems
//!   come online.
//! - `SubmissionFlags` as a `#[repr(transparent)]` `u32` bit-set with
//!   associated constants. Hand-rolled to avoid pulling `bitflags` into
//!   the workspace; the surface is small enough that the macro would pay
//!   for itself only once more subsystems need it.
//! - `NarfStatus` with the spec-mandated variants. Values are permanent.
//! - `Tag(pub u64)` newtype for submission↔completion correlation.
//! - `SubmissionQueue<N>` / `CompletionQueue<N>` thin aliases over
//!   `narf_ipc::Producer` / `Consumer`. Ring sizes are const-generic so
//!   the same layout serves both directions.
//!
//! Non-goals for Wave 2 (flagged in the report back):
//!
//! - The cancellation protocol of §3.1 is **not** implemented here —
//!   only `OpCode::Cancel` and the `NarfStatus::{Cancelled, CancelRequested}`
//!   discriminants exist. The submission-handle Future / Drop wiring
//!   that turns those into a uniform cooperative-cancel protocol is
//!   Wave 3 (it needs a real cap-table + in-kernel dispatcher).
//! - Bootstrap (§3.1 first block): `BootstrapRequest` / `BootstrapReply`
//!   live with the slow-path `svc`/`syscall` handler in `frame/` and
//!   are not yet landed.
//! - `OpCode` coverage is a starter set; every new subsystem adds its
//!   opcodes here.
//! - Overflow-flag wiring, doorbell attributes (WC / Device-nGnRE),
//!   UIPI / `UMWAIT` / `WFE` doorbell delivery — all live below this
//!   crate in `ipc/` and `memory/`. `abi/` only names the ring types.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

#[cfg(feature = "native-ring")]
use alloc::sync::Arc;
#[cfg(feature = "native-ring")]
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_capabilities::{CapError, CapSlot};
use narf_ipc::{Consumer, Producer};

// Re-export the shared-ring primitive so callers that already depend
// on narf-abi (e.g. narf-userspace) can reach `SharedRing` /
// `SharedProducer` / `SharedConsumer` without adding a direct
// narf-ipc dep — adding one perturbs link-time test-registration
// ordering in the verification harness.
pub use narf_ipc::{
    SharedConsumer, SharedProducer, SharedRing, SharedTryRecvError, SharedTrySendError,
};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_tracing::FnTime;

mod tests;

/// Per-call latency accumulator for `Dispatcher::dispatch_one`.
/// Exposed for read-back by tests / observability: a `FnTime` gives
/// a running Welford mean + variance plus a log2-bucket histogram so
/// callers can observe ABI dispatch cost without rebuilding the
/// kernel. The accumulator is global because the dispatcher is a
/// singleton in spec §3 — once SMP-sharded dispatch lands, a per-CPU
/// array will replace this.
pub static ABI_DISPATCH_LATENCY: FnTime = FnTime::new("abi::dispatch_one");

/// Latency accumulator for the slow-path pre-check — deliberately
/// separate from `ABI_DISPATCH_LATENCY` so the arithmetic cost of the
/// cancel-chain consume/enter is observable in isolation.
pub static ABI_CANCEL_CHECK_LATENCY: FnTime = FnTime::new("abi::cancel_check");

// ── Cooperative cancellation token ─────────────────────────────────
//
// Spec §3.1: every long-running op is cooperatively cancellable.
// Stage-4 only consulted the pending-cancel registry at dispatch
// time. Stage-5 wires a per-inflight `CancelToken` the dispatcher
// hands the op body so a mid-op cancel observed by an `OpCode::Cancel`
// arriving on a parallel submission is seen by the in-flight op the
// next time it polls. Bridges and async ops poll the token between
// meaningful steps and return `Cancelled` / `CancelRequested` per
// the CANCELLABLE flag on the submission.
//
// Concept reference: POSIX deferred-cancellation rationale — a
// cancellation point is somewhere the op explicitly checks for a
// pending cancel and unwinds. No GPL sources cited.

/// Per-inflight cancel flag. Set by `OpCode::Cancel` when the
/// dispatcher matches the target tag against the inflight token
/// table. Op bodies (or bridges) poll via `CancelCtx`.
#[derive(Debug)]
pub struct CancelToken {
    tag: u64,
    requested: AtomicBool,
}

impl CancelToken {
    /// Construct a fresh token for `tag`. Initial state: not requested.
    #[inline]
    pub fn new(tag: Tag) -> Self {
        Self {
            tag: tag.raw(),
            requested: AtomicBool::new(false),
        }
    }

    /// Tag this token guards.
    #[inline]
    pub fn tag(&self) -> Tag {
        Tag(self.tag)
    }

    /// Mark cancellation requested. Idempotent.
    #[inline]
    pub fn request(&self) {
        self.requested.store(true, Ordering::Release);
    }

    /// Has cancellation been requested?
    #[inline]
    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}

/// Borrowed cancel context handed to a long-running op body /
/// bridge. Polled between meaningful steps; a `true` return means
/// the op should unwind and return `Cancelled` (if CANCELLABLE was
/// set) or `CancelRequested` (otherwise; the op continues, then the
/// dispatcher converts the outcome).
#[derive(Copy, Clone, Debug)]
pub struct CancelCtx<'a> {
    token: Option<&'a CancelToken>,
}

impl<'a> CancelCtx<'a> {
    /// Construct a context that wraps a live token.
    #[inline]
    pub const fn from_token(token: &'a CancelToken) -> Self {
        Self { token: Some(token) }
    }

    /// Construct a detached context for callers off the ABI hot path
    /// (e.g. the slow-path `sys_ring_kick` shim). Never reports a
    /// cancel request; the slow path doesn't see mid-op cancels.
    #[inline]
    pub const fn detached() -> Self {
        Self { token: None }
    }

    /// Has cancellation been requested for the inflight op this
    /// context is bound to? Returns `false` on a detached context.
    #[inline]
    pub fn is_cancel_requested(&self) -> bool {
        match self.token {
            Some(t) => t.is_requested(),
            None => false,
        }
    }
}

// ── File-op delegate ──────────────────────────────────────────────
//
// The Dispatcher delegates `OpCode::OpenFile`/`Read`/`Write`/`Close`
// to a kernel-installed bridge fn so the same code path that backs
// the int-0x80 / svc-#0 syscalls also serves ABI-ring submissions.
// Boot wires `narf_userspace::handlers::abi_file_op_bridge` here;
// without it the dispatcher returns `InvalidOp`.

/// Numeric tag of the file op the bridge is being asked to
/// perform. Closed enum — these are abi-internal wire tags for the
/// io_uring-shaped dispatcher, not user-visible syscall numbers.
/// (The kernel-side bridge translates each tag to the platform's
/// `narf_userspace::Syscall::*.raw()` syscall number at dispatch.)
/// abi/ stays arch-neutral and can't depend on userspace, so these
/// stay pinned here rather than re-using the per-arch
/// `LINUX_TABLE` numbers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FileOpKind {
    Open = 110,
    Read = 111,
    Write = 112,
    Close = 113,
    Mmap = 120,
    Munmap = 121,
}

/// 6-arg payload + a return slot. Mirrors the
/// `Submission::inline` / `Completion::result` shape so the bridge
/// can route between the two without knowing about either.
#[derive(Copy, Clone, Debug, Default)]
pub struct FileOpArgs {
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct FileOpReturn {
    pub status: u32, // 0 = Ok, 1 = InvalidOp, ... — mirrors NarfStatus.
    pub value: u64,
}

#[cfg(feature = "native-ring")]
pub type FileOpBridge =
    fn(Option<DispatchContext<'_>>, FileOpKind, &FileOpArgs, &CancelCtx<'_>) -> FileOpReturn;

#[cfg(feature = "native-ring")]
static FILE_OP_BRIDGE: IrqSafeSpinLock<Option<FileOpBridge>> = IrqSafeSpinLock::new(None);

/// Install the bridge that routes ring-submitted file ops into the
/// kernel's regular syscall path. Boot calls this once with
/// `narf_userspace::handlers::abi_file_op_bridge`. The bridge is
/// handed a `CancelCtx` it polls between meaningful steps.
#[cfg(feature = "native-ring")]
pub fn install_file_op_bridge(bridge: FileOpBridge) {
    *FILE_OP_BRIDGE.lock() = Some(bridge);
}

#[cfg(feature = "native-ring")]
fn dispatch_file_op(
    subject: Option<DispatchContext<'_>>,
    kind: FileOpKind,
    args: &FileOpArgs,
    cx: &CancelCtx<'_>,
) -> FileOpReturn {
    let bridge = *FILE_OP_BRIDGE.lock();
    match bridge {
        Some(b) => b(subject, kind, args, cx),
        None => FileOpReturn {
            status: 1, /* InvalidOp */
            value: 0,
        },
    }
}

// ── CPU-power op bridge ────────────────────────────────────────────
//
// Same shape as the file-op bridge: kernel installs a callback at
// boot, the dispatcher routes every `OpCode::Cpu*` / `Rapl*` here.
// The kernel-side handler lives in `narf_power::syscall::handle`
// and applies the cap + current-CPU policy before forwarding to
// the relevant `power` module.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CpuOpKind {
    Topology = 0x20,
    PerfState = 0x21,
    RaplEnergy = 0x22,
    LatencyHint = 0x30,
    LatencyRelease = 0x31,
    SetFreqRange = 0x40,
    SetEpp = 0x41,
    SetGovernor = 0x42,
    SetEnergyBudget = 0x50,
    ClearEnergyBudget = 0x51,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct CpuOpArgs {
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
}

/// Bridge return — `status` mirrors `NarfStatus`; `result` is the
/// 6-slot payload that travels in the Completion's `result[]`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuOpReturn {
    pub status: u32,
    pub result: [u64; 6],
}

pub type CpuOpBridge = fn(CpuOpKind, &CpuOpArgs, &CancelCtx<'_>) -> CpuOpReturn;

static CPU_OP_BRIDGE: IrqSafeSpinLock<Option<CpuOpBridge>> = IrqSafeSpinLock::new(None);

pub fn install_cpu_op_bridge(bridge: CpuOpBridge) {
    *CPU_OP_BRIDGE.lock() = Some(bridge);
}

#[cfg(feature = "native-ring")]
fn dispatch_cpu_op(kind: CpuOpKind, args: &CpuOpArgs, cx: &CancelCtx<'_>) -> CpuOpReturn {
    let bridge = *CPU_OP_BRIDGE.lock();
    match bridge {
        Some(b) => b(kind, args, cx),
        None => CpuOpReturn {
            status: 1, /* InvalidOp */
            result: [0; 6],
        },
    }
}

// ── OpCode ──────────────────────────────────────────────────────────
//
// `#[repr(u32)]` with explicit discriminants: the wire tag is the byte
// value of `op`, not the source-order of the variant. Reordering must
// never change what a receiver sees — this is the same rule that
// `CapKind` in `capabilities/` §3.1 lives under.

/// Wire-stable operation tag. Subsystems that add opcodes append here
/// with an explicit discriminant; renumbering an existing variant is an
/// ABI break per spec §4 ("An ABI change is a breaking change").
#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OpCode {
    /// No-op; exercises the round-trip path. Completes with `Ok`.
    Noop = 0x0000,

    /// Cancel an outstanding submission by tag. Per spec §3.1, the
    /// cancel op itself always succeeds (`Ok`); the target either
    /// drains with `Cancelled`, `CancelRequested`, `Ok`, or an error.
    Cancel = 0x0001,

    /// Push a message into the named ring (the ring is in `caps[0]`).
    RingSend = 0x0002,

    /// Pop a message from the named ring (ring in `caps[0]`).
    RingRecv = 0x0003,

    /// Cooperative yield: complete immediately but let the scheduler
    /// reorder the task behind peers. Useful as a fairness primitive
    /// from userland without a syscall trap.
    Yield = 0x0004,

    /// Enter a protection domain named by `caps[0]` (a `Cap<Domain, _>`).
    /// Slow-path-only in the v0.2 spec; the fast-path form is a
    /// Wave-3+ compiler-assisted optimisation.
    DomainEnter = 0x0005,

    /// Exit the current protection domain; inverse of `DomainEnter`.
    DomainExit = 0x0006,

    /// Grant-gated cap transfer between tasks (capabilities/ §9.1,
    /// #1363 wiring). `caps[0]` is the sender's Grant cap for the
    /// object, `caps[1]` is the cap to transfer, `inline[0]` is the
    /// target task id. Both presented slots resolve against the
    /// submitting task's own table first (the §8 gate at dispatch
    /// entry); on success `result[0]` is the receiver's fresh
    /// task-local slot number (>= 16). The sender retains its slot
    /// (sharing semantics).
    CapTransfer = 0x0007,

    /// File ops mirror `narf_userspace::Syscall`'s file numbers.
    /// Inline operands match: `inline[0]=fd or path-ptr`,
    /// `inline[1]=path-len or buf-ptr`, etc. `Completion::result[0]`
    /// is the bytes-read/written or new fd, like `SyscallReturn::value`.
    OpenFile = 0x0010,
    Read = 0x0011,
    Write = 0x0012,
    Close = 0x0013,

    /// Memory ops. `inline[0..3]` carry the args; `Completion::result[0]`
    /// is the mapped vaddr (Mmap) or 0 (Munmap).
    Mmap = 0x0014,
    Munmap = 0x0015,

    // ── CPU power-management ops (`narf_power::syscall`) ─────────
    //
    // Phase 1 (Tier 0 read-only):
    //   `inline[0]` = cpu_id (or `CPU_ID_CURRENT = u64::MAX`).
    //   On success, `result[]` carries the decoded payload.
    /// Read system topology. `result[0]` = cpu count;
    /// `result[1]` = package count; further details delivered out
    /// of band via the topology-bridge user buffer (caller-supplied
    /// in `inline[1..3]` — base pointer + capacity).
    CpuTopology = 0x0020,
    /// Snapshot of one CPU's perf state. See
    /// `narf_power::syscall::pack_perf_state` for the result layout.
    CpuPerfState = 0x0021,
    /// Read RAPL energy counter for `inline[1]` = RaplDomain.
    /// `result[0]` = joules × 1e6 (microjoules).
    RaplEnergy = 0x0022,

    // Phase 2 (Tier 1 latency hints):
    /// Register a max-idle-latency hint. `inline[0]` = max idle
    /// microseconds. `result[0]` = `LatencyToken`.
    CpuIdleLatencyHint = 0x0030,
    /// Release a previously-issued LatencyToken. `inline[0]` =
    /// token id.
    CpuIdleRelease = 0x0031,

    // Phase 3 (Tier 2 frequency control):
    /// `inline[0]` = cpu_id; `inline[1]` = min KHz; `inline[2]` = max KHz.
    CpuSetFreqRange = 0x0040,
    /// `inline[0]` = cpu_id; `inline[1]` = EPP (low byte 0..=255).
    CpuSetEpp = 0x0041,
    /// `inline[0]` = cpu_id; `inline[1]` = `Governor` discriminant.
    CpuSetGovernor = 0x0042,

    // Phase 4 (Tier 3 energy budget):
    /// `inline[0]` = RaplDomain; `inline[1]` = power-cap window
    /// in milliseconds; `inline[2]` = energy budget per window in
    /// joules × 1000.
    CpuSetEnergyBudget = 0x0050,
    /// Release any energy budget the caller installed.
    CpuClearEnergyBudget = 0x0051,
}

impl OpCode {
    /// Raw u32 discriminant — useful for tracing / audit dumps.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Per-op required domain — capabilities/ §8 step 5 (#1547).
    ///
    /// The domain the calling task's active domain must match for the
    /// op to dispatch (`Err(DomainMismatch)` otherwise — see
    /// `check_submission_domain`). The table lives here, in `abi/`,
    /// because `capabilities/` cannot name the `DomainId` type
    /// (namespace owned by security-model/ §4.1) and neither the
    /// `CapSlot` wire format (frozen, capabilities/ §8 v1.0) nor the
    /// object-table entry records a domain — so the check belongs at
    /// dispatch, where the calling task's active domain is known
    /// (the bound `CallerAuthority` logical domain).
    ///
    /// Assignment rule, grounded in security-model/ §4.1 ownership:
    /// every op in the enum today is submitted by a user task through
    /// its rings, and dispatch is kernel-side handling of that task's
    /// own ring submissions — the per-task kernel-side state
    /// (`USERSPACE_K`: "cap table mirror, ABI ring control") is what
    /// the op acts on. So every user-submittable op requires
    /// `USERSPACE_K`: a submission from a task active in any other
    /// domain (a driver domain, the FRAME/TCB domain, `KEYS`, …) is
    /// a domain confusion, not a user operation. In-subsystem
    /// authorisation is untouched by this leg: the power ops still
    /// enforce their own `narf_power` rules, the file ops their fd
    /// rules, `CapTransfer` its Grant gate.
    ///
    /// `None` = domain-agnostic: `DomainEnter` / `DomainExit` are
    /// domain-*transition* ops whose target domain is dynamic —
    /// named by `caps[0]`, a `Cap<Domain>` — so no static required
    /// domain exists for them. Their step-5 leg (target-domain match)
    /// needs the `Domain` cap type, which does not exist in-tree yet
    /// (neither does a dispatch arm: both ops currently complete
    /// `InvalidOp`); that is an explicit remainder, not a silent
    /// skip. Future ops that belong to another domain (driver-only,
    /// `KEYS`-only) get their `Some(...)` entry here when they land.
    pub const fn required_domain(self) -> Option<DomainId> {
        match self {
            OpCode::DomainEnter | OpCode::DomainExit => None,
            _ => Some(DomainId::USERSPACE_K),
        }
    }
}

// ── SubmissionFlags ─────────────────────────────────────────────────
//
// `#[repr(transparent)]` over `u32` keeps the submission layout tight
// (4 bytes after `op`). Hand-rolled bit-set: `bitflags` would add a
// workspace dependency for three flags. If the flag surface grows past
// a handful, swap to the crate.

/// Submission flags bit-set. Values are permanent (they appear in
/// `Submission::flags` on the wire).
#[repr(transparent)]
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct SubmissionFlags(u32);

impl SubmissionFlags {
    /// Empty flag set.
    pub const NONE: SubmissionFlags = SubmissionFlags(0);

    /// Target op accepts `OpCode::Cancel` requests. Ops missing this
    /// bit that receive a cancel complete with `CancelRequested`.
    pub const CANCELLABLE: SubmissionFlags = SubmissionFlags(1 << 0);

    /// Next submission in the ring is part of the same chain; cancel
    /// cascades across the chain per spec §3.1 "Linked submissions".
    pub const LINKED: SubmissionFlags = SubmissionFlags(1 << 1);

    /// Drain: operation waits until all earlier submissions have
    /// produced terminal completions before starting. Useful for
    /// fence-like barriers.
    pub const DRAIN: SubmissionFlags = SubmissionFlags(1 << 2);

    /// Raw u32 representation.
    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Construct from a raw u32. Unknown bits are preserved verbatim;
    /// subsystems are responsible for validating their own bits on
    /// drain. This mirrors `CapKind` — unknown-tag rejection lives at
    /// the dispatcher, not at the wire-decoder.
    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Test whether every bit in `other` is set in `self`.
    #[inline]
    pub const fn contains(self, other: SubmissionFlags) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Bitwise OR.
    #[inline]
    pub const fn union(self, other: SubmissionFlags) -> Self {
        Self(self.0 | other.0)
    }

    /// Bitwise AND.
    #[inline]
    pub const fn intersection(self, other: SubmissionFlags) -> Self {
        Self(self.0 & other.0)
    }
}

impl core::fmt::Debug for SubmissionFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Print as `SubmissionFlags(0xNN | CANCELLABLE | LINKED)`. The
        // raw hex is the wire tag; names make the value human-readable.
        f.debug_tuple("SubmissionFlags")
            .field(&format_args!("{:#x}", self.0))
            .finish()
    }
}

impl core::ops::BitOr for SubmissionFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl core::ops::BitAnd for SubmissionFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        self.intersection(rhs)
    }
}

impl core::ops::BitOrAssign for SubmissionFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

// ── NarfStatus ──────────────────────────────────────────────────────
//
// Pinned discriminants so completion decoders on the user side can
// read a bare `u32` without relying on Rust layout rules.

/// Completion status. Values are permanent — see spec §4 (ABI change
/// rules). `Ok`, `Pending`, and the cancel-family variants are the
/// minimum set Wave-2 needs; richer status codes come with their
/// subsystems.
#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NarfStatus {
    /// Operation completed successfully. `result` carries the payload.
    Ok = 0x0000,

    /// Operation has not completed yet. Only valid on the in-kernel
    /// side — a user-visible completion never carries `Pending`.
    Pending = 0x0001,

    /// Cancellation took effect. `result` MUST report durable side
    /// effects (spec §3.1 "Partial-completion disclosure").
    Cancelled = 0x0002,

    /// Operation was observed cancellation but will keep running
    /// (fence / flush / commit). Caller awaits a later terminal
    /// completion.
    CancelRequested = 0x0003,

    /// Underlying cap was revoked between enqueue and dispatch.
    /// Authoritative — do NOT retry (spec §4).
    CapRevoked = 0x0004,

    /// OpCode was not recognised by the in-kernel dispatcher.
    InvalidOp = 0x0005,

    /// Target resource is busy — caller may retry.
    Busy = 0x0006,

    /// Target ring / endpoint has been closed.
    Closed = 0x0007,

    /// Caller's cap doesn't permit the requested action (e.g. a
    /// non-TCB attempt to address a CPU other than its own).
    Forbidden = 0x0008,

    /// The hardware doesn't expose the knob the request is asking
    /// to turn (e.g. CpuSetEpp on a CPU with no HWP / CPPC, or
    /// CpuSetEnergyBudget on a system with no RAPL). Distinct from
    /// `InvalidOp` (which means the OpCode itself is unknown) —
    /// the syscall is well-formed, the silicon just can't do it.
    Unsupported = 0x0009,
}

impl NarfStatus {
    /// Raw u32 discriminant — wire tag.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

// ── Tag ─────────────────────────────────────────────────────────────

/// Correlation tag between a `Submission` and its `Completion`.
/// Producer-chosen, echoed by the kernel into `Completion::tag`
/// unchanged. The kernel does not assume uniqueness — collision
/// handling is a userspace concern — but collisions make cancellation
/// ambiguous, so userspace convention is "monotone per ring".
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Tag(pub u64);

impl Tag {
    /// Construct a tag from its raw u64.
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Raw u64 representation.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

// ── Submission ──────────────────────────────────────────────────────
//
// Layout (spec §3 field order, with Rust's `#[repr(C)]` alignment rules
// applied — the naive 4+4+64+8+48 = 128 undercounts the two padding
// runs forced by `CapSlot`'s 16-alignment):
//
//   op:      u32                       offset   0, size  4
//   flags:   u32                       offset   4, size  4
//   <interior pad>                     offset   8, size  8   (CapSlot is 16-aligned)
//   caps:    [CapSlot; 4]              offset  16, size 64
//   tag:     u64                       offset  80, size  8
//   inline:  [u64; 6]                  offset  88, size 48
//   <tail pad>                         offset 136, size  8   (struct is 16-aligned)
//   total size = 144, align = 16 (inherited from CapSlot)
//
// The interior and tail pads are both forced by `CapSlot`'s
// 16-alignment. A spec revision that wants a 128-byte total can reorder
// so `caps` leads and drop a cap slot, but that changes the on-wire
// field order and is a Wave-3+ decision. The const asserts below pin
// the actual layout so silent drift is caught at build time.

/// Submission-ring entry. Wire layout is fixed by `#[repr(C)]`; the
/// `const _ = assert!(size_of == 144)` pin below catches any drift.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Submission {
    /// Operation tag. `#[repr(u32)]` keeps this a plain 4-byte integer
    /// in the wire layout even though it is a Rust enum.
    pub op: OpCode,
    /// Flag bit-set — see `SubmissionFlags`.
    pub flags: SubmissionFlags,
    /// Capabilities referenced by this op. Unused slots are `CapSlot::EMPTY`.
    pub caps: [CapSlot; 4],
    /// User-chosen correlation tag. Echoed in `Completion::tag`.
    pub tag: u64,
    /// Six inline u64 operands. Subsystems document the meaning per op.
    pub inline: [u64; 6],
}

impl Submission {
    /// Inline operand count; part of the stable ABI.
    pub const INLINE_WORDS: usize = 6;

    /// Cap slot count per submission.
    pub const CAP_SLOTS: usize = 4;

    /// Construct an empty noop submission with a given tag.
    #[inline]
    pub const fn noop(tag: Tag) -> Self {
        Self {
            op: OpCode::Noop,
            flags: SubmissionFlags::NONE,
            caps: [CapSlot::EMPTY; 4],
            tag: tag.raw(),
            inline: [0; 6],
        }
    }

    /// Construct a cancel submission: `tag` is this submission's own
    /// correlation tag, `target` is the tag of the outstanding
    /// submission to cancel. Per spec §3.1 the cancel op itself
    /// always succeeds with `Ok`; the target's terminal completion
    /// reports `Cancelled` / `CancelRequested` / `Ok` separately.
    #[inline]
    pub const fn cancel(tag: Tag, target: Tag) -> Self {
        let mut inline = [0u64; 6];
        inline[0] = target.raw();
        Self {
            op: OpCode::Cancel,
            flags: SubmissionFlags::NONE,
            caps: [CapSlot::EMPTY; 4],
            tag: tag.raw(),
            inline,
        }
    }

    /// Target tag for an `OpCode::Cancel` submission (inline[0]). Calling
    /// on a non-cancel submission returns the inline[0] value as-is —
    /// this is a structural accessor, not a type check.
    #[inline]
    pub const fn cancel_target(&self) -> Tag {
        Tag(self.inline[0])
    }

    /// Return the correlation tag as a `Tag`.
    #[inline]
    pub const fn tag(&self) -> Tag {
        Tag(self.tag)
    }
}

// Wire-format pins — break if the layout silently drifts.
const _: () = assert!(core::mem::size_of::<Submission>() == 144);
const _: () = assert!(core::mem::align_of::<Submission>() == 16);

// ── Completion ──────────────────────────────────────────────────────
//
// Layout (spec §3):
//   tag:    u64                      offset  0, size  8
//   status: u32                      offset  8, size  4
//   <4 bytes tail padding before result's 8-byte alignment>
//   result: [u64; 6]                 offset 16, size 48
//   total size = 64, align = 8
//
// Status is `#[repr(u32)]`; Rust inserts the 4-byte padding to align
// `result`. The size pin below catches any reshuffle.

/// Completion-ring entry. Wire layout fixed by `#[repr(C)]`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Completion {
    /// Echoed from the originating `Submission::tag`.
    pub tag: u64,
    /// Completion status — see `NarfStatus`.
    pub status: NarfStatus,
    /// Six result words. Meaning is per-op; on `Cancelled`, reports
    /// durable side effects per spec §3.1 "Partial-completion disclosure".
    pub result: [u64; 6],
}

impl Completion {
    /// Result operand count; part of the stable ABI.
    pub const RESULT_WORDS: usize = 6;

    /// Construct an Ok completion for a given tag, empty result.
    #[inline]
    pub const fn ok(tag: Tag) -> Self {
        Self {
            tag: tag.raw(),
            status: NarfStatus::Ok,
            result: [0; 6],
        }
    }

    /// Construct a completion with a given status and result.
    #[inline]
    pub const fn with(tag: Tag, status: NarfStatus, result: [u64; 6]) -> Self {
        Self {
            tag: tag.raw(),
            status,
            result,
        }
    }

    /// Return the correlation tag as a `Tag`.
    #[inline]
    pub const fn tag(&self) -> Tag {
        Tag(self.tag)
    }
}

// Wire-format pins — break if the layout silently drifts.
const _: () = assert!(core::mem::size_of::<Completion>() == 64);
const _: () = assert!(core::mem::align_of::<Completion>() == 8);

// ── Ring aliases ────────────────────────────────────────────────────
//
// A ring pair per task: submissions flow user → kernel, completions
// kernel → user. Each direction is a `narf_ipc::{Producer, Consumer}`
// — SPSC, explicit release/acquire pair per index transition.
//
// The `const N` capacity is intentionally exposed here so callers pick
// the ring size at construction; the spec does not pin it. Powers of
// two only; the underlying `Ring` asserts this at compile time.

/// User-side submission-queue producer. Enqueues `Submission` entries;
/// kernel-side drainer is a matching `SubmissionDrain<N>`.
pub type SubmissionQueue<const N: usize> = Producer<Submission, N>;

/// Kernel-side submission-queue drainer. Reads `Submission` entries
/// produced by a matching `SubmissionQueue<N>`.
pub type SubmissionDrain<const N: usize> = Consumer<Submission, N>;

/// Kernel-side completion-queue producer. Enqueues `Completion`
/// entries for a user task to drain.
pub type CompletionQueue<const N: usize> = Producer<Completion, N>;

/// User-side completion-queue drainer.
pub type CompletionDrain<const N: usize> = Consumer<Completion, N>;

// Submission / Completion are flat `#[repr(C)]` POD records: their
// only fields are integers, `CapSlot` indices, and inline u64s. No
// raw pointers cross domains here, so the MTE retag-on-publish hook
// is the trait's default identity body.
impl narf_ipc::Retag for Submission {}
impl narf_ipc::Retag for Completion {}

/// Create a fresh submission ring-pair (user → kernel direction).
/// Thin passthrough to `narf_ipc::channel` so callers do not have to
/// name the payload type.
pub fn submission_channel<const N: usize>() -> (SubmissionQueue<N>, SubmissionDrain<N>) {
    narf_ipc::channel::<Submission, N>()
}

/// Create a fresh completion ring-pair (kernel → user direction).
pub fn completion_channel<const N: usize>() -> (CompletionQueue<N>, CompletionDrain<N>) {
    narf_ipc::channel::<Completion, N>()
}

/// Build the right cancellation outcome for a submission given its
/// flags. Spec §3.1: CANCELLABLE → `Cancelled`; non-CANCELLABLE →
/// `CancelRequested` (op kept running, caller awaits eventual Ok).
#[cfg(feature = "native-ring")]
fn cancel_outcome(tag: Tag, flags: SubmissionFlags) -> Completion {
    let status = if flags.contains(SubmissionFlags::CANCELLABLE) {
        NarfStatus::Cancelled
    } else {
        NarfStatus::CancelRequested
    };
    Completion::with(tag, status, [0; 6])
}

// ── Dispatcher ──────────────────────────────────────────────────────

/// Map a capability error to the completion status dispatch reports.
///
/// - `Revoked` → `CapRevoked`: the authoritative "do NOT retry"
///   status (spec §4) — the object was revoked between enqueue and
///   dispatch, or the task has no table at all.
/// - `TypeMismatch` / `RightsTooWeak` / `DomainMismatch` /
///   `ObjectMismatch` → `Forbidden`: the presented cap does not
///   permit the requested action.
/// - `CapTableFull` → `Busy`: lookup never returns it; a transfer
///   into a full receiver table is the only producer, and `Busy`
///   ("caller may retry") is the least-wrong status — the receiver
///   may make room by other means, and no narrower status exists.
pub fn cap_error_status(e: CapError) -> NarfStatus {
    match e {
        CapError::Revoked => NarfStatus::CapRevoked,
        CapError::CapTableFull => NarfStatus::Busy,
        _ => NarfStatus::Forbidden,
    }
}

/// §8 step 5 (domain-tag match). Pure function over the op's
/// required domain (`OpCode::required_domain`) and the calling task's
/// active domain — the two facts dispatch must compare. An op with no
/// required domain (`DomainEnter` / `DomainExit`, whose target domain
/// is dynamic) always passes; any other op passes only when the
/// active domain equals the required one, else
/// `Err(CapError::DomainMismatch)`. Dispatch maps that to
/// `NarfStatus::Forbidden` via `cap_error_status` (an unknown owner —
/// no registered task — maps to `CapRevoked` instead, at the call
/// sites). Kept separate from `validate_submission_caps` so both the
/// pure table and the pure comparison are unit-testable without a
/// scheduler, and so the step order in §8 (steps 1–4, then 5) is
/// visible at the call sites.
pub fn check_submission_domain(op: OpCode, active_domain: DomainId) -> Result<(), CapError> {
    match op.required_domain() {
        None => Ok(()),
        Some(required) if required == active_domain => Ok(()),
        Some(_) => Err(CapError::DomainMismatch),
    }
}

/// Borrowed request subject. Kernel-owned references never cross the wire.
#[derive(Clone, Copy, Debug)]
#[cfg(feature = "native-ring")]
pub struct DispatchContext<'a> {
    pub authority: &'a narf_scheduler::CallerAuthority,
    pub image: u64,
}
#[cfg(feature = "native-ring")]
impl<'a> DispatchContext<'a> {
    pub const fn new(authority: &'a narf_scheduler::CallerAuthority, image: u64) -> Self {
        Self { authority, image }
    }
    pub fn validate(&self, sub: &Submission) -> Result<(), NarfStatus> {
        self.authority
            .domain_for_image(self.image)
            .map_err(cap_error_status)?;
        self.authority
            .validate_caps(&sub.caps)
            .map_err(cap_error_status)?;
        let domain = self
            .authority
            .domain_for_image(self.image)
            .map_err(cap_error_status)?;
        check_submission_domain(sub.op, domain).map_err(cap_error_status)
    }
}

/// Compatibility helper for explicit owner handles. A missing owner rejects
/// every presented cap; production dispatch uses DispatchContext::validate,
/// which locks a nonempty owner's table once for the fixed cap array.
#[cfg(feature = "native-ring")]
pub fn validate_submission_caps(
    owner: Option<&narf_scheduler::CallerAuthority>,
    caps: &[CapSlot; 4],
) -> Result<(), NarfStatus> {
    for presented in caps.iter() {
        if presented.is_empty() {
            continue;
        }
        let Some(owner) = owner else {
            return Err(NarfStatus::Forbidden);
        };
        owner.lookup(*presented).map_err(cap_error_status)?;
    }
    Ok(())
}

/// Compare an explicitly bound owner's current logical domain with the op's
/// required domain. Production DispatchContext also pins the image generation.
/// None is reserved for legacy kernel-test fixtures.
#[cfg(feature = "native-ring")]
pub fn check_owner_domain(
    owner: Option<&narf_scheduler::CallerAuthority>,
    op: OpCode,
) -> Result<(), NarfStatus> {
    let Some(owner) = owner else {
        return Ok(());
    };
    let image = owner.image().map_err(cap_error_status)?;
    let domain = owner.domain_for_image(image).map_err(cap_error_status)?;
    check_submission_domain(op, domain).map_err(cap_error_status)
}

/// Pending-cancel registry — tags whose producers have issued an
/// `OpCode::Cancel`. The dispatcher consults this before running each
/// submission's op body: a hit short-circuits the op with `Cancelled`
/// (for ops that carry `SubmissionFlags::CANCEL_AWARE`) or
/// `CancelRequested` (for ops that don't).
///
/// Stage-3 single-task dispatch: the cancel is observed only when its
/// target has not yet been dequeued. Stage-4's concurrent dispatcher
/// will widen this into per-inflight-tag cancel flags so mid-op
/// cancellation can interrupt a long-running await.
#[derive(Debug)]
#[cfg(feature = "native-ring")]
struct PendingCancels {
    inner: IrqSafeSpinLock<CancelInner>,
}

#[derive(Debug)]
#[cfg(feature = "native-ring")]
struct CancelInner {
    /// Tags directly targeted by an `OpCode::Cancel`.
    tags: Vec<u64>,
    /// Chain ids whose members should propagate to `Cancelled` —
    /// spec §3.1 "Linked submissions" rule.
    chains: Vec<u32>,
    /// tag → chain_id map for the submissions that have been
    /// dispatched (or are being dispatched). Cancel propagation looks
    /// a target's tag up here to find its chain and then marks the
    /// whole chain.
    chain_of: Vec<(u64, u32)>,
    /// Id assigned to the most recently seen chain. A new submission
    /// with `SubmissionFlags::LINKED` inherits this id; a submission
    /// without `LINKED` starts a fresh chain.
    last_chain: u32,
    /// Monotonic chain-id allocator; starts at 1 so `last_chain == 0`
    /// unambiguously means "no chain seen yet".
    next_chain: u32,
    /// Live cancel tokens for ops currently inside `dispatch_one`.
    /// `OpCode::Cancel` flips the `requested` flag on the matching
    /// entry so the in-flight op observes the cancel the next time
    /// its bridge polls `CancelCtx::is_cancel_requested`.
    inflight: Vec<Arc<CancelToken>>,
}

#[cfg(feature = "native-ring")]
impl PendingCancels {
    const fn new() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(CancelInner {
                tags: Vec::new(),
                chains: Vec::new(),
                chain_of: Vec::new(),
                last_chain: 0,
                next_chain: 1,
                inflight: Vec::new(),
            }),
        }
    }

    /// Register a fresh inflight cancel token for `tag`. Called at
    /// the top of `dispatch_one` so a parallel `OpCode::Cancel` can
    /// flip the token while the op body runs. If the cancel already
    /// fired (tag is in `tags` or its chain is in `chains`), the
    /// returned token is pre-set so the op observes the cancel on
    /// its very first poll.
    fn enter_inflight(&self, tag: Tag, chain: u32) -> Arc<CancelToken> {
        let mut g = self.inner.lock();
        let tok = Arc::new(CancelToken::new(tag));
        let pre_cancelled = g.tags.contains(&tag.raw()) || g.chains.contains(&chain);
        if pre_cancelled {
            tok.request();
        }
        g.inflight.push(tok.clone());
        tok
    }

    /// Deregister an inflight token at the bottom of `dispatch_one`.
    fn exit_inflight(&self, tag: Tag) {
        let mut g = self.inner.lock();
        if let Some(pos) = g.inflight.iter().position(|t| t.tag == tag.raw()) {
            g.inflight.swap_remove(pos);
        }
    }

    /// Flip the cancel flag on any inflight token whose tag matches.
    /// Also propagates across linked chain members.
    fn signal_inflight(&self, target: Tag) {
        let g = self.inner.lock();
        let chain_id = g
            .chain_of
            .iter()
            .find(|&&(t, _)| t == target.raw())
            .map(|&(_, c)| c);
        for tok in g.inflight.iter() {
            if tok.tag == target.raw() {
                tok.request();
                continue;
            }
            if let Some(cid) = chain_id {
                let tc = g
                    .chain_of
                    .iter()
                    .find(|&&(t, _)| t == tok.tag)
                    .map(|&(_, c)| c);
                if tc == Some(cid) {
                    tok.request();
                }
            }
        }
    }

    /// Determine the chain id for a newly-arrived submission. Called
    /// at dispatch time. `LINKED` extends the previous chain;
    /// otherwise a fresh chain id is minted. Records the tag→chain
    /// mapping so a later `OpCode::Cancel(tag)` can find it.
    ///
    /// `OpCode::Cancel` submissions are transparent to the chain
    /// tracker — they neither consume a chain id nor update
    /// `last_chain`. A cancel issued mid-chain must not displace the
    /// `LINKED`-inheritance of the next real op, because the cancel
    /// is a control message that lives outside the chain's I/O
    /// semantics (spec §3.1 "Linked submissions" talks about chained
    /// *operations*, not cancel requests).
    fn enter(&self, sub: &Submission) -> u32 {
        if sub.op == OpCode::Cancel {
            return 0; // sentinel — cancel doesn't belong to a chain
        }
        let mut g = self.inner.lock();
        let chain = if sub.flags.contains(SubmissionFlags::LINKED) && g.last_chain != 0 {
            g.last_chain
        } else {
            let id = g.next_chain;
            g.next_chain = g.next_chain.saturating_add(1);
            id
        };
        g.last_chain = chain;
        g.chain_of.push((sub.tag, chain));
        chain
    }

    /// Record a cancel request for `target`. Looks up the target's
    /// chain (if any) and marks the whole chain cancel-pending so
    /// linked peers are auto-cancelled on dispatch.
    fn request(&self, target: Tag) {
        let mut g = self.inner.lock();
        if !g.tags.iter().any(|&x| x == target.raw()) {
            g.tags.push(target.raw());
        }
        if let Some(&(_, chain)) = g.chain_of.iter().find(|&&(t, _)| t == target.raw()) {
            if !g.chains.contains(&chain) {
                g.chains.push(chain);
            }
        }
    }

    /// Consume any cancel-pending state for `tag` / `chain`; returns
    /// `true` iff this submission should short-circuit. Consuming the
    /// tag side avoids re-cancelling a late retry with the same tag;
    /// chain side stays marked so every member of the chain propagates.
    fn consume(&self, tag: Tag, chain: u32) -> bool {
        let mut g = self.inner.lock();
        let mut hit = false;
        if let Some(pos) = g.tags.iter().position(|&x| x == tag.raw()) {
            g.tags.swap_remove(pos);
            hit = true;
        }
        if g.chains.contains(&chain) {
            hit = true;
        }
        hit
    }
}

#[cfg(feature = "native-ring")]
fn binding_live(
    authority: Option<&narf_scheduler::CallerAuthority>,
    image: Option<u64>,
    lease: Option<&AtomicBool>,
) -> bool {
    !lease.is_some_and(|closed| closed.load(Ordering::Acquire))
        && authority
            .is_none_or(|owner| image.is_some_and(|image| owner.domain_for_image(image).is_ok()))
}

/// In-kernel ABI dispatcher. Drains a submission ring and dispatches
/// to the appropriate subsystems.
#[derive(Debug)]
#[cfg(feature = "native-ring")]
pub struct Dispatcher<const N: usize> {
    sq: SubmissionDrain<N>,
    cq: CompletionQueue<N>,
    pending: PendingCancels,
    /// Identity retained for diagnostics and unknown-owner rejection. The
    /// authority below supplies all admission facts, without resolving this id.
    owner: Option<narf_scheduler::TaskId>,
    authority: Option<Arc<narf_scheduler::CallerAuthority>>,
    image: Option<u64>,
    lease: Option<Arc<AtomicBool>>,
    watch: Option<Arc<narf_scheduler::AuthorityWatch>>,
}

#[cfg(feature = "native-ring")]
impl<const N: usize> Dispatcher<N> {
    /// Legacy constructor. Production submissions fail closed until bound;
    /// kernel-test fixtures may dispatch empty-cap operations without an owner.
    pub const fn new(sq: SubmissionDrain<N>, cq: CompletionQueue<N>) -> Self {
        Self {
            sq,
            cq,
            pending: PendingCancels::new(),
            owner: if cfg!(feature = "kernel-test") {
                None
            } else {
                Some(narf_scheduler::TaskId::NONE)
            },
            authority: None,
            image: None,
            lease: None,
            watch: None,
        }
    }

    /// Create a dispatcher bound to the submitting task `owner`.
    /// Every non-empty cap in a submission is resolved against
    /// `owner`'s own table before the op body runs; a task can
    /// therefore never spend another task's capabilities through
    /// this dispatcher. The op's required domain is likewise checked
    /// against `owner`'s active domain (§8 step 5, #1547). This is
    /// the production constructor — `spawn_dispatcher_for` binds the
    /// task Bootstrap minted the rings for.
    pub fn for_task(
        sq: SubmissionDrain<N>,
        cq: CompletionQueue<N>,
        owner: narf_scheduler::TaskId,
    ) -> Self {
        match narf_scheduler::task_authority(owner) {
            Some(authority) => Self::for_authority(sq, cq, authority, None),
            None => Self {
                sq,
                cq,
                pending: PendingCancels::new(),
                owner: Some(owner),
                authority: None,
                image: None,
                lease: None,
                watch: None,
            },
        }
    }

    /// Bind once using the task-owned authority rather than an identity index.
    pub fn for_authority(
        sq: SubmissionDrain<N>,
        cq: CompletionQueue<N>,
        authority: Arc<narf_scheduler::CallerAuthority>,
        lease: Option<Arc<AtomicBool>>,
    ) -> Self {
        let image = authority.image().ok();
        let watch = Some(authority.watch());
        Self {
            sq,
            cq,
            pending: PendingCancels::new(),
            owner: Some(authority.task_id()),
            authority: Some(authority),
            image,
            lease,
            watch,
        }
    }

    fn subject(&self) -> Result<Option<DispatchContext<'_>>, NarfStatus> {
        if self
            .lease
            .as_ref()
            .is_some_and(|closed| closed.load(Ordering::Acquire))
        {
            return Err(NarfStatus::CapRevoked);
        }
        match (&self.authority, self.image, self.owner) {
            (Some(authority), Some(image), _) => {
                authority
                    .domain_for_image(image)
                    .map_err(cap_error_status)?;
                Ok(Some(DispatchContext::new(authority, image)))
            }
            (_, _, Some(_)) => Err(NarfStatus::CapRevoked),
            _ => Ok(None),
        }
    }

    /// Run the dispatch loop. Never returns unless the submission ring
    /// is closed.
    pub async fn run(&mut self) {
        loop {
            // A retirement/session-close wake also releases an idle SQ or a
            // full CQ. Register only when queue polling actually blocks, and
            // recheck afterward to close the wake-before-register race.
            let received = {
                let authority = self.authority.as_deref();
                let image = self.image;
                let lease = self.lease.as_deref();
                let watch = self.watch.as_deref();
                let live = || binding_live(authority, image, lease);
                let mut receive = core::pin::pin!(self.sq.recv());
                core::future::poll_fn(|cx| {
                    if !live() {
                        return core::task::Poll::Ready(None);
                    }
                    match core::future::Future::poll(receive.as_mut(), cx) {
                        core::task::Poll::Ready(result) => core::task::Poll::Ready(result.ok()),
                        core::task::Poll::Pending => {
                            if let Some(watch) = watch {
                                watch.register(cx);
                            }
                            if live() {
                                core::task::Poll::Pending
                            } else {
                                core::task::Poll::Ready(None)
                            }
                        }
                    }
                })
                .await
            };
            let Some(sub) = received else {
                break;
            };
            let completion = self.dispatch_one(sub).await;
            let delivered = {
                let authority = self.authority.as_deref();
                let image = self.image;
                let lease = self.lease.as_deref();
                let watch = self.watch.as_deref();
                let live = || binding_live(authority, image, lease);
                let mut send = core::pin::pin!(self.cq.send(completion));
                core::future::poll_fn(|cx| {
                    if !live() {
                        return core::task::Poll::Ready(false);
                    }
                    match core::future::Future::poll(send.as_mut(), cx) {
                        core::task::Poll::Ready(result) => core::task::Poll::Ready(result.is_ok()),
                        core::task::Poll::Pending => {
                            if let Some(watch) = watch {
                                watch.register(cx);
                            }
                            if live() {
                                core::task::Poll::Pending
                            } else {
                                core::task::Poll::Ready(false)
                            }
                        }
                    }
                })
                .await
            };
            if !delivered {
                break;
            }

            // 4. Quiescent state: we've finished one "ABI syscall"
            // and hold no cross-await RCU guards.
            narf_rcu::report_quiescent();
        }
    }

    /// Dispatch a single submission.
    async fn dispatch_one(&mut self, sub: Submission) -> Completion {
        let _g = narf_tracing::fntime::scope(&ABI_DISPATCH_LATENCY);
        let tag = sub.tag();
        // Cap gate first (capabilities/ §8 steps 1–4, #1363 wiring):
        // every presented cap resolves against the submitting task's
        // own table before any op body — or cancel bookkeeping — can
        // observe the submission. A failure short-circuits with the
        // cap status; the op never runs.
        let admission = self.subject().and_then(|subject| match subject {
            Some(subject) => subject.validate(&sub),
            None => validate_submission_caps(None, &sub.caps),
        });
        if let Err(status) = admission {
            return Completion::with(tag, status, [0; 6]);
        }
        // Enter the sub into the chain registry; assigns a chain id
        // (fresh or inherited from LINKED) and records tag→chain so a
        // later `OpCode::Cancel` can propagate across the chain.
        let chain = {
            let _g = narf_tracing::fntime::scope(&ABI_CANCEL_CHECK_LATENCY);
            self.pending.enter(&sub)
        };

        // Cancel-protocol pre-check (spec §3.1): if this submission's
        // tag was already cancel-pending, or any linked peer already
        // triggered a chain cancel, short-circuit. Ops that carry
        // `CANCELLABLE` complete `Cancelled`; all others complete
        // `CancelRequested` — the spec's non-cancellable path.
        // `OpCode::Cancel` itself bypasses the check (cancelling a
        // cancel is a no-op whose completion still always succeeds).
        if sub.op != OpCode::Cancel && self.pending.consume(tag, chain) {
            return cancel_outcome(tag, sub.flags);
        }

        // Register a per-inflight cancel token so a parallel
        // `OpCode::Cancel(tag)` can flip it while the body runs.
        // `OpCode::Cancel` itself does not register — it is the
        // signaller, not a cancellation target.
        let token = if sub.op != OpCode::Cancel {
            Some(self.pending.enter_inflight(tag, chain))
        } else {
            None
        };

        let completion = match sub.op {
            OpCode::Noop => Completion::ok(tag),

            OpCode::Cancel => {
                // §3.1: cancel always succeeds; the target's terminal
                // completion reports the outcome separately.
                // `request` also marks the target's whole chain so
                // linked peers auto-cancel; `signal_inflight` flips
                // the per-inflight token so a mid-op poll observes
                // the cancel.
                let target = sub.cancel_target();
                self.pending.request(target);
                self.pending.signal_inflight(target);
                Completion::ok(tag)
            }

            OpCode::CapTransfer => {
                // §9.1 Grant-gated transfer via the ABI. The §8 gate
                // above already resolved caps[0] (Grant) and caps[1]
                // against the sender's table; this re-resolves both
                // and installs the resolved entry into the receiver's
                // table. `inline[0]` is the target task id;
                // `result[0]` is the receiver's fresh slot number.
                // No `return` here: the bottom of `dispatch_one`
                // deregisters the inflight token, and this arm must
                // flow through it like every other arm.
                match self.owner {
                    None => Completion::with(tag, NarfStatus::Forbidden, [0; 6]),
                    Some(owner) => {
                        let target = narf_scheduler::TaskId(sub.inline[0]);
                        let result = narf_scheduler::task_authority(target)
                            .ok_or(CapError::Revoked)
                            .and_then(|target| {
                                self.authority
                                    .as_ref()
                                    .ok_or(CapError::Revoked)?
                                    .transfer_to(&target, sub.caps[0], sub.caps[1])
                            });
                        let _ = owner;
                        match result {
                            Ok(slot) => {
                                let mut result = [0u64; 6];
                                result[0] = u64::from(slot);
                                Completion::with(tag, NarfStatus::Ok, result)
                            }
                            Err(e) => Completion::with(tag, cap_error_status(e), [0; 6]),
                        }
                    }
                }
            }

            OpCode::Yield => {
                narf_scheduler::yield_now().await;
                let cancelled = token.as_ref().map(|t| t.is_requested()).unwrap_or(false);
                if cancelled {
                    cancel_outcome(tag, sub.flags)
                } else {
                    Completion::ok(tag)
                }
            }

            OpCode::OpenFile
            | OpCode::Read
            | OpCode::Write
            | OpCode::Close
            | OpCode::Mmap
            | OpCode::Munmap => {
                let kind = match sub.op {
                    OpCode::OpenFile => FileOpKind::Open,
                    OpCode::Read => FileOpKind::Read,
                    OpCode::Write => FileOpKind::Write,
                    OpCode::Close => FileOpKind::Close,
                    OpCode::Mmap => FileOpKind::Mmap,
                    OpCode::Munmap => FileOpKind::Munmap,
                    _ => unreachable!(),
                };
                let args = FileOpArgs {
                    a0: sub.inline[0],
                    a1: sub.inline[1],
                    a2: sub.inline[2],
                    a3: sub.inline[3],
                    a4: sub.inline[4],
                    a5: sub.inline[5],
                };
                let cx = match token.as_ref() {
                    Some(t) => CancelCtx::from_token(t),
                    None => CancelCtx::detached(),
                };
                let r = dispatch_file_op(self.subject().ok().flatten(), kind, &args, &cx);
                // Bridge may have observed the cancel and returned
                // status=2 (Cancelled). Translate per CANCELLABLE.
                match r.status {
                    0 => {
                        let mut result = [0u64; 6];
                        result[0] = r.value;
                        Completion::with(tag, NarfStatus::Ok, result)
                    }
                    2 => cancel_outcome(tag, sub.flags),
                    _ => Completion::with(tag, NarfStatus::InvalidOp, [0; 6]),
                }
            }

            OpCode::CpuTopology
            | OpCode::CpuPerfState
            | OpCode::RaplEnergy
            | OpCode::CpuIdleLatencyHint
            | OpCode::CpuIdleRelease
            | OpCode::CpuSetFreqRange
            | OpCode::CpuSetEpp
            | OpCode::CpuSetGovernor
            | OpCode::CpuSetEnergyBudget
            | OpCode::CpuClearEnergyBudget => {
                let kind = match sub.op {
                    OpCode::CpuTopology => CpuOpKind::Topology,
                    OpCode::CpuPerfState => CpuOpKind::PerfState,
                    OpCode::RaplEnergy => CpuOpKind::RaplEnergy,
                    OpCode::CpuIdleLatencyHint => CpuOpKind::LatencyHint,
                    OpCode::CpuIdleRelease => CpuOpKind::LatencyRelease,
                    OpCode::CpuSetFreqRange => CpuOpKind::SetFreqRange,
                    OpCode::CpuSetEpp => CpuOpKind::SetEpp,
                    OpCode::CpuSetGovernor => CpuOpKind::SetGovernor,
                    OpCode::CpuSetEnergyBudget => CpuOpKind::SetEnergyBudget,
                    OpCode::CpuClearEnergyBudget => CpuOpKind::ClearEnergyBudget,
                    _ => unreachable!(),
                };
                let args = CpuOpArgs {
                    a0: sub.inline[0],
                    a1: sub.inline[1],
                    a2: sub.inline[2],
                    a3: sub.inline[3],
                    a4: sub.inline[4],
                    a5: sub.inline[5],
                };
                let cx = match token.as_ref() {
                    Some(t) => CancelCtx::from_token(t),
                    None => CancelCtx::detached(),
                };
                let r = dispatch_cpu_op(kind, &args, &cx);
                match r.status {
                    0 => Completion::with(tag, NarfStatus::Ok, r.result),
                    2 => cancel_outcome(tag, sub.flags),
                    5 => Completion::with(tag, NarfStatus::InvalidOp, r.result),
                    8 => Completion::with(tag, NarfStatus::Forbidden, r.result),
                    9 => Completion::with(tag, NarfStatus::Unsupported, r.result),
                    _ => Completion::with(tag, NarfStatus::InvalidOp, r.result),
                }
            }

            _ => {
                // unrecognized opcode.
                Completion::with(tag, NarfStatus::InvalidOp, [0; 6])
            }
        };

        if token.is_some() {
            self.pending.exit_inflight(tag);
        }
        completion
    }

    /// Count of cancel requests that have been recorded but not yet
    /// consumed by a matching submission. Diagnostic surface for tests
    /// and tracing; not load-bearing for dispatch semantics.
    pub fn pending_cancels(&self) -> usize {
        let g = self.pending.inner.lock();
        g.tags.len()
    }

    /// Test/observability hook: request mid-op cancellation of a
    /// currently-inflight submission by tag. Returns `true` iff an
    /// inflight token was found and signalled. An `OpCode::Cancel`
    /// wire submission triggers the same path internally.
    pub fn request_inflight_cancel(&self, target: Tag) -> bool {
        let g = self.pending.inner.lock();
        let mut hit = false;
        for tok in g.inflight.iter() {
            if tok.tag == target.raw() {
                tok.request();
                hit = true;
            }
        }
        hit
    }
}
