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

use narf_capabilities::CapSlot;
use narf_ipc::{Consumer, Producer};

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
    Noop         = 0x0000,

    /// Cancel an outstanding submission by tag. Per spec §3.1, the
    /// cancel op itself always succeeds (`Ok`); the target either
    /// drains with `Cancelled`, `CancelRequested`, `Ok`, or an error.
    Cancel       = 0x0001,

    /// Push a message into the named ring (the ring is in `caps[0]`).
    RingSend     = 0x0002,

    /// Pop a message from the named ring (ring in `caps[0]`).
    RingRecv     = 0x0003,

    /// Cooperative yield: complete immediately but let the scheduler
    /// reorder the task behind peers. Useful as a fairness primitive
    /// from userland without a syscall trap.
    Yield        = 0x0004,

    /// Enter a protection domain named by `caps[0]` (a `Cap<Domain, _>`).
    /// Slow-path-only in the v0.2 spec; the fast-path form is a
    /// Wave-3+ compiler-assisted optimisation.
    DomainEnter  = 0x0005,

    /// Exit the current protection domain; inverse of `DomainEnter`.
    DomainExit   = 0x0006,
}

impl OpCode {
    /// Raw u32 discriminant — useful for tracing / audit dumps.
    #[inline]
    pub const fn as_u32(self) -> u32 { self as u32 }
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
    pub const LINKED:      SubmissionFlags = SubmissionFlags(1 << 1);

    /// Drain: operation waits until all earlier submissions have
    /// produced terminal completions before starting. Useful for
    /// fence-like barriers.
    pub const DRAIN:       SubmissionFlags = SubmissionFlags(1 << 2);

    /// Raw u32 representation.
    #[inline]
    pub const fn bits(self) -> u32 { self.0 }

    /// Construct from a raw u32. Unknown bits are preserved verbatim;
    /// subsystems are responsible for validating their own bits on
    /// drain. This mirrors `CapKind` — unknown-tag rejection lives at
    /// the dispatcher, not at the wire-decoder.
    #[inline]
    pub const fn from_bits(bits: u32) -> Self { Self(bits) }

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
        f.debug_tuple("SubmissionFlags").field(&format_args!("{:#x}", self.0)).finish()
    }
}

impl core::ops::BitOr for SubmissionFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self { self.union(rhs) }
}

impl core::ops::BitAnd for SubmissionFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self { self.intersection(rhs) }
}

impl core::ops::BitOrAssign for SubmissionFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
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
    Ok               = 0x0000,

    /// Operation has not completed yet. Only valid on the in-kernel
    /// side — a user-visible completion never carries `Pending`.
    Pending          = 0x0001,

    /// Cancellation took effect. `result` MUST report durable side
    /// effects (spec §3.1 "Partial-completion disclosure").
    Cancelled        = 0x0002,

    /// Operation was observed cancellation but will keep running
    /// (fence / flush / commit). Caller awaits a later terminal
    /// completion.
    CancelRequested  = 0x0003,

    /// Underlying cap was revoked between enqueue and dispatch.
    /// Authoritative — do NOT retry (spec §4).
    CapRevoked       = 0x0004,

    /// OpCode was not recognised by the in-kernel dispatcher.
    InvalidOp        = 0x0005,

    /// Target resource is busy — caller may retry.
    Busy             = 0x0006,

    /// Target ring / endpoint has been closed.
    Closed           = 0x0007,
}

impl NarfStatus {
    /// Raw u32 discriminant — wire tag.
    #[inline]
    pub const fn as_u32(self) -> u32 { self as u32 }
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
    pub const fn new(raw: u64) -> Self { Self(raw) }

    /// Raw u64 representation.
    #[inline]
    pub const fn raw(self) -> u64 { self.0 }
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
    pub op:     OpCode,
    /// Flag bit-set — see `SubmissionFlags`.
    pub flags:  SubmissionFlags,
    /// Capabilities referenced by this op. Unused slots are `CapSlot::EMPTY`.
    pub caps:   [CapSlot; 4],
    /// User-chosen correlation tag. Echoed in `Completion::tag`.
    pub tag:    u64,
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
            op:     OpCode::Noop,
            flags:  SubmissionFlags::NONE,
            caps:   [CapSlot::EMPTY; 4],
            tag:    tag.raw(),
            inline: [0; 6],
        }
    }

    /// Return the correlation tag as a `Tag`.
    #[inline]
    pub const fn tag(&self) -> Tag { Tag(self.tag) }
}

// Wire-format pins — break if the layout silently drifts.
const _: () = assert!(core::mem::size_of::<Submission>()  == 144);
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
    pub tag:    u64,
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
        Self { tag: tag.raw(), status: NarfStatus::Ok, result: [0; 6] }
    }

    /// Construct a completion with a given status and result.
    #[inline]
    pub const fn with(tag: Tag, status: NarfStatus, result: [u64; 6]) -> Self {
        Self { tag: tag.raw(), status, result }
    }

    /// Return the correlation tag as a `Tag`.
    #[inline]
    pub const fn tag(&self) -> Tag { Tag(self.tag) }
}

// Wire-format pins — break if the layout silently drifts.
const _: () = assert!(core::mem::size_of::<Completion>()  == 64);
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

// ── Dispatcher ──────────────────────────────────────────────────────

/// In-kernel ABI dispatcher. Drains a submission ring and dispatches
/// to the appropriate subsystems.
#[derive(Debug)]
pub struct Dispatcher<const N: usize> {
    sq: SubmissionDrain<N>,
    cq: CompletionQueue<N>,
}

impl<const N: usize> Dispatcher<N> {
    /// Create a new dispatcher from a ring pair.
    pub fn new(sq: SubmissionDrain<N>, cq: CompletionQueue<N>) -> Self {
        Self { sq, cq }
    }

    /// Run the dispatch loop. Never returns unless the submission ring
    /// is closed.
    pub async fn run(&mut self) {
        loop {
            // 1. Receive next submission.
            let Ok(sub) = self.sq.recv().await else {
                // User-side dropped their SQ producer; EOF.
                break;
            };

            // 2. Dispatch.
            let completion = self.dispatch_one(sub).await;

            // 3. Post completion.
            // If the user-side dropped their CQ consumer, we can't
            // deliver anymore; terminate.
            if self.cq.send(completion).await.is_err() {
                break;
            }

            // 4. Quiescent state: we've finished one "ABI syscall"
            // and hold no cross-await RCU guards.
            narf_rcu::report_quiescent();
        }
    }

    /// Dispatch a single submission.
    async fn dispatch_one(&mut self, sub: Submission) -> Completion {
        let tag = sub.tag();

        match sub.op {
            OpCode::Noop => {
                Completion::ok(tag)
            }

            OpCode::Yield => {
                narf_scheduler::yield_now().await;
                Completion::ok(tag)
            }

            _ => {
                // unrecognized opcode.
                Completion::with(tag, NarfStatus::InvalidOp, [0; 6])
            }
        }
    }
}
