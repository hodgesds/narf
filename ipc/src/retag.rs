//! Pointer-retag hook for slot publish.
//!
//! On aarch64 with MTE, a pointer transferred across an IPC ring is
//! still tagged with the *producer*'s logical tag — if the consumer
//! lives in a different MTE domain it would tag-fault on first
//! dereference. The fix is to re-tag the pointer (and write the new
//! tag to the granule's tag storage) at publish time, so the
//! consumer receives a pointer carrying a logical tag that matches
//! its own domain's view of the granule.
//!
//! Stable Rust can't reflect over `T`'s fields and can't combine a
//! blanket `impl<T> Retag for T` with type-specific overrides. The
//! pragmatic surface is: a trait with an identity default body, and
//! `Producer<T: Retag>` bounds. Every payload type opts in by writing
//! `impl Retag for MyType {}` (taking the default identity) or
//! overrides `retag` to retag its pointer fields via
//! `narf_arch::aarch64::mte::{irg, stg}`.
//!
//! See ARM DDI0487 D6.2 / D6.5 for the tag-field placement and
//! granule-tag semantics, and Arm's MTE whitepaper for the
//! cross-domain-handoff rationale.

/// Per-pointer retag hook for ring payloads. Default body is the
/// identity; types whose payload includes raw pointers override
/// `retag` and call `narf_arch::aarch64::mte::{irg, stg}` per field.
pub trait Retag: Sized {
    #[inline(always)]
    fn retag(self) -> Self {
        self
    }
}

/// Slot-publish retag entry point. Bound-aware passthrough; dispatch
/// is on the concrete `T: Retag` impl.
#[inline(always)]
pub fn retag_on_publish<T: Retag>(msg: T) -> T {
    msg.retag()
}

// ── default identity impls for primitives ──────────────────────────
//
// These let existing ring payloads (u8, u64, …) continue to work
// without per-call-site changes. Aggregates introduced elsewhere
// (e.g. `narf_abi::Submission`) impl `Retag` in their own crate.

macro_rules! retag_identity {
    ($($t:ty),* $(,)?) => {
        $( impl Retag for $t {} )*
    };
}

retag_identity!(u8, u16, u32, u64, u128, usize);
retag_identity!(i8, i16, i32, i64, i128, isize);
retag_identity!(bool, char, ());

impl<T> Retag for *const T {}
impl<T> Retag for *mut T {}

impl<T: Retag, const N: usize> Retag for [T; N] {
    #[inline(always)]
    fn retag(self) -> Self {
        self.map(Retag::retag)
    }
}
