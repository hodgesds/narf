//! The context structure an OOM policy program reads.
//!
//! # Why a structure and not arguments
//!
//! A struct_ops method's arguments are packed into the context tuple, which is
//! `MAX_CTX_WORDS` — four — words wide. `badness` used all four (pid, RSS,
//! `oom_score_adj`, total pages) and had no room for anything else, which meant
//! every additional thing a policy might reasonably weigh — how much of the
//! victim is actually resident, how much of it is writable anonymous memory
//! that reclaim cannot get back, which cgroup it belongs to — was unreachable
//! by construction rather than by choice.
//!
//! A region ctx lifts that ceiling: the program enters with `(data, data_end)`
//! over one of these structures and reads fields out of it, so the width of the
//! context is the width of the struct. The cost is that a program must prove
//! each read in bounds (`data + offset + 8 <= data_end`) — the same obligation
//! an XDP program discharges before touching a packet byte, and the reason a
//! hostile program cannot read past the end of what the hook published.
//!
//! # ABI
//!
//! `#[repr(C)]`, every field eight bytes, no padding — the offsets below are
//! the ones a compiled program uses:
//!
//! | Offset | Field | |
//! |---|---|---|
//! | 0  | `pid` | process id |
//! | 8  | `tid` | thread the kill lands on |
//! | 16 | `rss_pages` | resident pages, the classic badness term |
//! | 24 | `oom_score_adj` | signed `-1000..=1000` bias |
//! | 32 | `total_pages` | frames in the machine, for scaling |
//! | 40 | `mapped_bytes` | mapped size, exact rather than page-rounded |
//! | 48 | `resident_pages` | pages with a live physical frame |
//! | 56 | `writable_nonexec_bytes` | the anonymous, reclaim-resistant part |
//!
//! **Fields are append-only.** A program compiled against offset 40 keeps
//! reading offset 40 for as long as it is loaded, so a field may be added at
//! the end and never inserted, reordered, or resized. Growing the struct is
//! backwards-compatible in the direction that matters: an old program's bounds
//! check still passes, and a new program run against an old kernel fails its
//! bounds check and falls back rather than reading rubbish.

use narf_bpf_structops::CtxStruct;

/// One candidate, as a policy program sees it.
///
/// See the module docs for the offsets and the append-only rule.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct OomCtx {
    /// Process id.
    pub pid: u64,
    /// Thread id the kill is delivered to.
    pub tid: u64,
    /// Resident pages as the candidate source reported them.
    pub rss_pages: u64,
    /// `oom_score_adj`, `-1000..=1000`. Signed; a program reading it as
    /// unsigned sees a very large number for a protected task, which is why
    /// `-1000` is enforced natively rather than left to the program.
    pub oom_score_adj: i64,
    /// Frames in the machine. Never 0, so a program may divide by it.
    pub total_pages: u64,
    /// Mapped bytes, unrounded — `rss_pages` is this divided by the page size,
    /// and a policy weighing many small mappings wants the remainder.
    pub mapped_bytes: u64,
    /// Pages with a live physical frame behind them. Lower than `rss_pages`
    /// for an address space with lazily-populated regions, so the difference
    /// is "how much killing this would actually free right now".
    pub resident_pages: u64,
    /// Writable, non-executable bytes: approximately the anonymous working set,
    /// the part page-cache reclaim cannot recover. A policy that wants to kill
    /// what reclaim cannot fix ranks on this rather than on `rss_pages`.
    pub writable_nonexec_bytes: u64,
}

// SAFETY: `#[repr(C)]` with eight 8-byte fields and 8-byte alignment, so it is
// padding-free — every byte the adapter copies is an initialised field, and a
// program reading the region cannot observe uninitialised stack. No pointers,
// references, or interior mutability: every field is a plain integer describing
// the candidate, so nothing here discloses a kernel address.
unsafe impl CtxStruct for OomCtx {}

/// Byte offset of each field, for programs and for the smokes that assert the
/// layout has not drifted.
pub mod offset {
    /// `pid`.
    pub const PID: i16 = 0;
    /// `tid`.
    pub const TID: i16 = 8;
    /// `rss_pages`.
    pub const RSS_PAGES: i16 = 16;
    /// `oom_score_adj`.
    pub const OOM_SCORE_ADJ: i16 = 24;
    /// `total_pages`.
    pub const TOTAL_PAGES: i16 = 32;
    /// `mapped_bytes`.
    pub const MAPPED_BYTES: i16 = 40;
    /// `resident_pages`.
    pub const RESIDENT_PAGES: i16 = 48;
    /// `writable_nonexec_bytes`.
    pub const WRITABLE_NONEXEC_BYTES: i16 = 56;
}

/// The structure's size, which is also the `data_end - data` a program sees.
pub const OOM_CTX_SIZE: usize = core::mem::size_of::<OomCtx>();

// The layout the table in the module docs promises, checked at compile time
// rather than trusted: a reordered or resized field would silently repoint
// every already-loaded program at different data.
const _: () = {
    assert!(
        OOM_CTX_SIZE == 64,
        "OomCtx grew a field without a doc update"
    );
    assert!(core::mem::align_of::<OomCtx>() == 8);
};
