//! Runtime arenas: the program-visible half of `memory::bpf_arena`.
//!
//! `memory/src/bpf_arena.rs` owns the kernel VA window, the slot layout, the
//! guards, and page population. It knows nothing about programs. This module is
//! the seam: it binds an arena to a loaded [`BpfProg`](crate::prog::BpfProg),
//! gives the interpreter a way to turn an in-program handle into a real address,
//! and hands the same pages to userspace through `FileOps::mmap_frames`.
//!
//! ## What an in-program arena pointer is
//!
//! A **slot-relative handle**, not an address. Linux stores a truncated absolute
//! *user* VA (`kernel/bpf/arena.c:16-42`), which is why `arena_map_mmap` returns
//! `-EBUSY` unless every process maps the arena at the same address. Here the
//! handle is an offset within the program's [`ArenaSlot`], so:
//!
//! * userspace may map the arena wherever it likes and add its own base;
//! * a pointer *stored inside* the arena means the same thing to the program,
//!   to the kernel, and to userspace — which is what makes a linked structure
//!   built by a program walkable through the shared mapping at all;
//! * the interpreter and a future JIT must agree on the handle's value, because
//!   of the previous point. The interpreter therefore does **not** bias arena
//!   pointers into a synthetic region the way it does the stack (`STACK_REGION`)
//!   and the context — see [`crate::interp`]'s address-model note, which says
//!   exactly what that costs.
//!
//! ## Pre-populated, not demand-populated
//!
//! Every page of a [`ProgArena`] is backed at creation, and that is not a
//! simplification that can be lifted where it stands. Two independent reasons:
//!
//! 1. Populating a page allocates a frame and walks page tables. Spec §4.6
//!    forbids allocation on the program-run path, which is entered from an XDP
//!    hook with a lock held and IRQs masked. So a program cannot fault a page in.
//! 2. `FileOps::mmap_frames` is eager and snapshot-based: it returns the frame
//!    list at `mmap` time and the syscall layer maps those frames SHARED. A page
//!    the program populated afterwards would simply not exist in the userspace
//!    mapping. `Arena::snapshot_frames` freezes the arena for exactly this
//!    reason (spec §8.2).
//!
//! Full population at creation makes both moot *and* buys the access path a
//! property it needs anyway: the accessible extent of an arena is a constant, so
//! resolving a handle is two comparisons with no lock and no allocation. The
//! `mmap_fault(offset)` hook spec §8.2 proposes is what would lift this, and it
//! is a filesystem-layer change.
//!
//! ## How a program gets its handle
//!
//! [`narf_arena_base`] returns [`ARENA_BASE_HANDLE`], which is a **constant of
//! the ABI**: every slot is laid out identically, so the first arena in every
//! slot begins at the same offset. The constant is not ambiguous even though it
//! is shared, because the runtime resolves it against *the running program's*
//! arenas — a program with no arena reaches nothing through it and gets
//! [`crate::interp::Trap::BadAccess`] on the first access, and a program can
//! never name another program's arena because the handle is slot-relative and
//! its slot is the only one it has.
//!
//! A kfunc cannot ask "which program is calling?" — the uniform shim ABI has no
//! program argument and no per-CPU current-program state exists — so returning a
//! constant is not a shortcut here, it is the only shape that works without
//! inventing that state. It is also the shape that makes the answer *per
//! program* at the only layer that knows: resolution.

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_capabilities::{Cap, Grant};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::bpf_arena::{
    Arena, ArenaCap, ArenaError, ArenaSlot, ARENA_NULL_GUARD_BYTES, ARENA_USABLE_BYTES,
};
use narf_memory::PhysAddr;

use crate::types::{ArenaPtr, BpfType};

/// The in-program handle of the first arena in every slot.
///
/// See the module docs: this is a constant because every slot has the same
/// layout, and it is unambiguous because resolution is per-program.
pub const ARENA_BASE_HANDLE: u64 = ARENA_NULL_GUARD_BYTES;

// The verifier bounds an arena displacement against its own copy of the window
// size, and `memory` cannot depend on the verifier to say so. This is the one
// place both constants are nameable, so it is where the equality is enforced
// rather than described: if they drift, `access()` accepts a displacement the
// slot's tail guard does not cover, and a verified program reaches the next
// program's arenas.
const _: () = assert!(
    ARENA_USABLE_BYTES == narf_bpf_verifier::ARENA_WINDOW_BYTES,
    "the verifier's arena displacement bound and the memory layer's usable slot \
     region must be the same number — see the tail-guard note in \
     memory/src/bpf_arena.rs"
);
// And the base handle must be inside the null guard's *upper* boundary, i.e. be
// exactly where the memory layer places the first arena. A mismatch would make
// every program's first access miss its own arena by a page.
const _: () = assert!(
    ARENA_BASE_HANDLE == ARENA_NULL_GUARD_BYTES,
    "ARENA_BASE_HANDLE must name the first byte the memory layer will place an \
     arena at"
);

/// The kernel's own authority to create arenas.
///
/// Minted once and leaked. `Cap::bootstrap()` allocates an object-table slot per
/// call, so calling it per arena would leak a slot per arena — and this is a
/// *kernel* authority anyway, distinct from the credential check `bpf(2)`
/// performs on the calling task.
pub fn kernel_arena_cap() -> &'static ArenaCap {
    static SLOT: IrqSafeSpinLock<Option<&'static ArenaCap>> = IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        let c: &'static _ = alloc::boxed::Box::leak(alloc::boxed::Box::new(Cap::<
            narf_memory::bpf_arena::BpfArena,
            Grant,
        >::bootstrap()));
        *g = Some(c);
    }
    g.expect("just installed")
}

/// A fully-populated arena bound to a program.
///
/// Wraps [`Arena`] and adds the two things a program needs from it: the handle
/// range it answers to, and the guarantee that every byte in that range is
/// backed — which is what lets [`ProgArena::resolve`] run with no lock on the
/// program-run path.
#[derive(Debug)]
pub struct ProgArena {
    arena: Arena,
    /// Slot-relative handle of byte 0. Cached rather than re-derived so the
    /// access path does not chase into `Arena`.
    base: u64,
    /// Accessible bytes. Equal to the declared size, because creation populates
    /// everything or fails.
    bytes: u64,
}

impl ProgArena {
    /// Create and fully populate an arena of `pages` pages inside `slot`.
    ///
    /// # Errors
    ///
    /// [`ArenaError`], including [`ArenaError::NoFrame`] if population runs out
    /// of memory partway — in which case nothing is returned and the partially
    /// populated arena is dropped, rather than a short arena being handed back.
    pub fn new(cap: &ArenaCap, slot: &ArenaSlot, pages: usize) -> Result<Arc<Self>, ArenaError> {
        cap.check_live().map_err(|_| ArenaError::CapRevoked)?;
        let arena = Arena::new_in(cap, slot, pages)?;
        // All of it, up front. See the module docs on why demand population is
        // not merely unimplemented but unreachable from a program.
        arena.populate_range(0, pages)?;
        let base = arena.base_offset();
        let bytes = arena.max_pages() * 4096;
        Ok(Arc::new(Self { arena, base, bytes }))
    }

    /// The handle of this arena's first byte. Never zero.
    #[inline]
    #[must_use]
    pub fn base_handle(&self) -> u64 {
        self.base
    }

    /// Accessible size in bytes.
    #[inline]
    #[must_use]
    pub fn len_bytes(&self) -> u64 {
        self.bytes
    }

    /// Kernel VA of byte 0 — the kernel's own view, never handed to a program.
    #[inline]
    #[must_use]
    pub fn kva(&self) -> u64 {
        self.arena.kva()
    }

    /// Resolve `handle..handle + len` to a kernel VA, or `None` if it is not
    /// entirely inside this arena.
    ///
    /// No lock and no allocation: the accessible extent is fixed at creation
    /// (see the module docs), so this is arithmetic. That is what makes it legal
    /// on the program-run path under §4.6.
    #[inline]
    #[must_use]
    pub fn resolve(&self, handle: u64, len: usize) -> Option<u64> {
        let off = handle.checked_sub(self.base)?;
        let end = off.checked_add(len as u64)?;
        if end > self.bytes {
            return None;
        }
        Some(self.arena.kva() + off)
    }

    /// The backing frames, in page order.
    ///
    /// Freezes the arena against further population — harmless here, since
    /// creation already populated everything.
    #[must_use]
    pub fn frames(&self) -> Vec<PhysAddr> {
        self.arena.snapshot_frames()
    }
}

/// Resolve a handle against every arena a program owns.
///
/// A linear scan, deliberately: a program has a handful of arenas, the scan is
/// branch-predictable, and the alternative — an interval tree — would allocate.
/// Returns `None` for the null guard, for a gap between arenas, and for anything
/// past the last one, which is what makes the interpreter's arena access
/// bounded by *this program's* arenas rather than by the window.
#[inline]
#[must_use]
pub fn resolve_in(arenas: &[Arc<ProgArena>], handle: u64, len: usize) -> Option<u64> {
    for a in arenas {
        if let Some(kva) = a.resolve(handle, len) {
            return Some(kva);
        }
    }
    None
}

/// Every arena one program can address, in one slot.
///
/// A group rather than a bare arena because the slot is the unit of addressing:
/// one pinned base register reaches everything in it, and the slot's tail guard
/// is what keeps a verified displacement from leaving it. See
/// `memory/src/bpf_arena.rs`.
#[derive(Debug)]
pub struct ArenaGroup {
    slot: ArenaSlot,
    arenas: Vec<Arc<ProgArena>>,
}

impl ArenaGroup {
    /// Reserve a slot with no arenas in it yet.
    ///
    /// # Errors
    ///
    /// [`ArenaError::CapRevoked`] if the capability is dead,
    /// [`ArenaError::SlotsUnreserved`] before `bpf_text::reserve_kernel_slots`,
    /// [`ArenaError::WindowExhausted`] if the window has no slot left.
    pub fn new(cap: &ArenaCap) -> Result<Self, ArenaError> {
        Ok(Self {
            slot: ArenaSlot::reserve(cap)?,
            arenas: Vec::new(),
        })
    }

    /// Reserve a slot and place one arena of `pages` pages in it.
    ///
    /// # Errors
    ///
    /// As [`ArenaGroup::new`] and [`ArenaGroup::add`].
    pub fn with_one(cap: &ArenaCap, pages: usize) -> Result<Self, ArenaError> {
        let mut g = Self::new(cap)?;
        g.add(cap, pages)?;
        Ok(g)
    }

    /// Add an arena to the group, after the ones already in it.
    ///
    /// # Errors
    ///
    /// [`ArenaError::SlotExhausted`] if the slot's usable region is full;
    /// otherwise as [`ProgArena::new`].
    pub fn add(&mut self, cap: &ArenaCap, pages: usize) -> Result<Arc<ProgArena>, ArenaError> {
        let a = ProgArena::new(cap, &self.slot, pages)?;
        self.arenas.push(Arc::clone(&a));
        Ok(a)
    }

    /// Every arena in the group, in placement order.
    #[inline]
    #[must_use]
    pub fn arenas(&self) -> &[Arc<ProgArena>] {
        &self.arenas
    }

    /// Kernel VA of the slot base — what a JIT would pin a register to.
    #[inline]
    #[must_use]
    pub fn slot_base(&self) -> u64 {
        self.slot.base()
    }
}

// The one kfunc the arena surface needs. Declared here rather than in
// `crate::kfuncs` so that the whole surface — the object, its resolution, its
// fd, and the kfunc that names it — reads as one thing. (A `///` comment here
// would attach to the macro invocation, which rustdoc drops.)
crate::kfunc! {
    /// The handle of this program's first arena.
    ///
    /// Returns a handle unconditionally, including for a program that has no
    /// arena; that program's first access through it fails
    /// [`resolve_in`] and the program is stopped with
    /// [`crate::interp::Trap::ArenaOutOfBounds`]. Reporting the absence here
    /// instead would need the shim to know which program is calling, which the
    /// uniform kfunc ABI does not express.
    #[context(Atomic)]
    pub fn narf_arena_base() -> ArenaPtr<u8> {
        // SAFETY: `BpfType::from_raw`'s obligation is that the register satisfy
        // `ArenaPtr::<u8>::DESC`, i.e. that it be a valid arena handle. This one
        // is produced by the kernel from the slot layout rather than by a
        // program, so the obligation is discharged by construction — this is the
        // only constructor `ArenaPtr` has, and it is `unsafe` because the *other*
        // caller (the shim's argument unpacking) is trusting the verifier.
        unsafe { <ArenaPtr<u8> as BpfType>::from_raw(ARENA_BASE_HANDLE, 0) }
    }
}

// ── the userspace mapping ──────────────────────────────────────────────

/// An arena behind an fd, so userspace can `mmap` it.
///
/// The anon-fd pattern, as `crate::prog::ProgFile` uses: an `Arc<dyn FileOps>`
/// with no backing file. `read`/`write` are unsupported — an arena is a mapping,
/// not a stream.
///
/// Installing this in an fd table is `bpf(2)`'s job and lives in
/// `narf-userspace`; this crate only supplies the type, exactly as it supplies
/// `ProgFile`.
#[derive(Debug)]
pub struct ArenaFile {
    arena: Arc<ProgArena>,
}

impl ArenaFile {
    /// Wrap an arena for installation in an fd table.
    #[must_use]
    pub fn new(arena: Arc<ProgArena>) -> Self {
        Self { arena }
    }

    /// The arena behind this fd.
    #[must_use]
    pub fn arena(&self) -> Arc<ProgArena> {
        Arc::clone(&self.arena)
    }
}

impl narf_filesystem::FileOps for ArenaFile {
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
            // So `fstat` tells userspace how much there is to map. The arena is
            // fully populated, so this is also the mappable extent.
            size: self.arena.len_bytes(),
            blocks: self.arena.len_bytes().div_ceil(512),
            mode: narf_filesystem::Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }

    /// The frames backing `[offset, offset + len)`, for a `MAP_SHARED` mapping.
    ///
    /// The syscall layer maps these borrowed and never frees them on `munmap`,
    /// which is correct here: the arena owns its frames for its whole life and
    /// the program is still writing to them.
    ///
    /// Whole-range and eager, which is all this arena needs *because* it is
    /// fully populated — see the module docs. An arena that grew after this
    /// call would have pages missing from the mapping, which is why
    /// `Arena::populate` refuses once the frames have been snapshotted.
    fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, narf_filesystem::FsError> {
        // The syscall layer page-aligns both, but this is a trust boundary for
        // a `Vec` index below, so it is checked rather than assumed.
        if offset % 4096 != 0 || len % 4096 != 0 || len == 0 {
            return Err(narf_filesystem::FsError::InvalidData);
        }
        let end = offset
            .checked_add(len as u64)
            .ok_or(narf_filesystem::FsError::InvalidData)?;
        if end > self.arena.len_bytes() {
            return Err(narf_filesystem::FsError::InvalidData);
        }
        let frames = self.arena.frames();
        let first = (offset / 4096) as usize;
        let count = len / 4096;
        // `frames()` is one entry per populated page in page order and the arena
        // is fully populated, so this range exists — but a short list would mean
        // handing userspace a mapping of somebody else's memory, so it is a
        // check and not an `expect`.
        let slice = frames
            .get(first..first + count)
            .ok_or(narf_filesystem::FsError::InvalidData)?;
        Ok(slice.iter().map(|p| p.as_u64()).collect())
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

// ── In-kernel smokes ───────────────────────────────────────────────────
//
// These live here rather than in `crate::tests` because they are the arena's
// own, and because every one of them needs a live MMU, a real frame allocator,
// and the boot-time slot reservation — none of which a host test has.

#[cfg(feature = "kernel-test")]
mod smokes {
    use super::*;

    use narf_bpf_isa::encode::encode;
    use narf_bpf_isa::{AtomicOp, CallTarget, Decoded, Insn, Reg, Size, Source};
    use narf_bpf_verifier::kfunc::Context;
    use narf_filesystem::FileOps;
    use narf_kernel_test::{kernel_test_in, TestResult};

    use narf_bpf_verifier::VerifyError;

    use crate::interp::{Outcome, Trap};
    use crate::prog::{BpfProg, BpfProgLoad, LoadError, LoadRequest};

    /// Node layout the linked-list smoke builds: `{ value, next }`, where `next`
    /// is a **handle** — the whole point of the exercise.
    const NODE_STRIDE: i16 = 16;
    const NODE_VALUE: i16 = 0;
    const NODE_NEXT: i16 = 8;

    fn r(n: u8) -> Reg {
        Reg::new(n).expect("register in range")
    }

    fn asm(items: &[Decoded]) -> Vec<Insn> {
        let mut out = Vec::new();
        for d in items {
            out.extend_from_slice(encode(*d).slots());
        }
        out
    }

    fn call_arena_base() -> Decoded {
        Decoded::Call(CallTarget::Kfunc(crate::kfunc::id_for("narf_arena_base")))
    }

    fn st_imm(dst: u8, off: i16, v: i32) -> Decoded {
        Decoded::Store {
            size: Size::Dw,
            dst: r(dst),
            off,
            src: Source::Imm(v),
        }
    }

    fn mov_imm(dst: u8, v: i32) -> Decoded {
        Decoded::Mov {
            wide: true,
            dst: r(dst),
            src: Source::Imm(v),
            sign_extend: None,
        }
    }

    fn atomic_add(off: i16, src: u8) -> Decoded {
        Decoded::Atomic {
            size: Size::Dw,
            op: AtomicOp::Add { fetch: false },
            dst: r(0),
            src: r(src),
            off,
        }
    }

    /// Minted once — `Cap::bootstrap()` costs an object-table slot per call.
    fn load_cap() -> &'static Cap<BpfProgLoad, Grant> {
        static SLOT: IrqSafeSpinLock<Option<&'static Cap<BpfProgLoad, Grant>>> =
            IrqSafeSpinLock::new(None);
        let mut g = SLOT.lock();
        if g.is_none() {
            let c: &'static _ =
                alloc::boxed::Box::leak(alloc::boxed::Box::new(
                    Cap::<BpfProgLoad, Grant>::bootstrap(),
                ));
            *g = Some(c);
        }
        g.expect("just installed")
    }

    fn request(name: &str, insns: Vec<Insn>) -> LoadRequest {
        LoadRequest {
            name: alloc::string::String::from(name),
            insns,
            context: Context::Atomic,
            // These arena smokes reference no maps. The field arrived with the
            // map work on a sibling branch; an empty list is what a program
            // with no `LD_IMM64` map reference carries.
            maps: alloc::vec::Vec::new(),
        }
    }

    /// What userspace sees: the frame list `mmap_frames` handed out, plus the base
    /// handle, and nothing else.
    ///
    /// Reads deliberately go through those *frames* and the kernel direct map,
    /// never through the arena's own VA window. That is the whole demonstration:
    /// the walk resolves handles against a base with no relation to the one the
    /// program used, which is exactly what a userspace mapping at an arbitrary
    /// address does — and what Linux's truncated-absolute-address arena pointer
    /// makes impossible (`arena_map_mmap` returns `-EBUSY` for a second address).
    struct SharedMapping {
        frames: Vec<u64>,
        base_handle: u64,
    }

    impl SharedMapping {
        fn read_u64(&self, handle: u64) -> Option<u64> {
            let off = handle.checked_sub(self.base_handle)?;
            let page = (off / 4096) as usize;
            let in_page = (off % 4096) as usize;
            if in_page + 8 > 4096 {
                return None;
            }
            let phys = *self.frames.get(page)?;
            let p = PhysAddr::new(phys).kernel_ptr::<u8>();
            let mut buf = [0u8; 8];
            // SAFETY: `phys` came from `mmap_frames`, so it is a frame this arena
            // owns for its whole life; `kernel_ptr` is the direct-map view of it,
            // and the bound above keeps the read inside that one page.
            unsafe {
                core::ptr::copy_nonoverlapping(p.add(in_page), buf.as_mut_ptr(), 8);
            }
            Some(u64::from_le_bytes(buf))
        }
    }

    /// Phase 3's gate: a program allocates in an arena, writes a linked
    /// structure, and the shared mapping walks it.
    ///
    /// "Allocates" is program-side by design — the plan makes the allocator an
    /// arena library rather than kernel code — so the program carves three nodes
    /// out of the arena it was given and links them by handle.
    fn smoke_bpf_arena_program_builds_list_walked_through_mapping() -> TestResult {
        let cap = kernel_arena_cap();
        let group = match ArenaGroup::with_one(cap, 2) {
            Ok(g) => Arc::new(g),
            Err(_) => return TestResult::Fail("ArenaGroup::with_one failed"),
        };
        let arena = Arc::clone(&group.arenas()[0]);
        let base = arena.base_handle();
        if base != ARENA_BASE_HANDLE {
            return TestResult::Fail("the first arena is not at the ABI base handle");
        }

        // Three nodes at handles base+0, base+16, base+32, linked forwards, the
        // last with a null next.
        let mut items = alloc::vec![call_arena_base()];
        for i in 0..3i16 {
            let value = 0x100 + i32::from(i);
            let next = if i == 2 {
                0
            } else {
                (base as i32) + i32::from((i + 1) * NODE_STRIDE)
            };
            items.push(st_imm(0, i * NODE_STRIDE + NODE_VALUE, value));
            items.push(st_imm(0, i * NODE_STRIDE + NODE_NEXT, next));
        }
        items.push(mov_imm(0, 3));
        items.push(Decoded::Exit);

        let prog = match BpfProg::load_with_arena(
            load_cap(),
            request("arena_list", asm(&items)),
            Some(Arc::clone(&group)),
        ) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("loading an arena program failed"),
        };
        // `jit_glue` gate 2: an arena program is never JITed, so the run below is
        // the interpreter's arena path and not native code's.
        if prog.is_jited() {
            return TestResult::Fail("an arena program must not be JITed");
        }
        if prog.run_atomic([0; 4], 4) != Some(Outcome::Returned(3)) {
            return TestResult::Fail("the arena program did not run to completion");
        }

        // Now the userspace side, through the frames and nothing else.
        let file = ArenaFile::new(Arc::clone(&arena));
        let frames = match file.mmap_frames(0, arena.len_bytes() as usize) {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("mmap_frames refused the whole arena"),
        };
        if frames.len() != 2 {
            return TestResult::Fail("mmap_frames returned the wrong number of frames");
        }
        let view = SharedMapping {
            frames,
            base_handle: base,
        };
        let mut handle = base;
        let mut sum = 0u64;
        let mut seen = 0usize;
        while handle != 0 {
            let Some(value) = view.read_u64(handle + NODE_VALUE as u64) else {
                return TestResult::Fail("the shared mapping could not read a node");
            };
            let Some(next) = view.read_u64(handle + NODE_NEXT as u64) else {
                return TestResult::Fail("the shared mapping could not read a next handle");
            };
            sum += value;
            seen += 1;
            if seen > 8 {
                return TestResult::Fail("the linked list did not terminate");
            }
            handle = next;
        }
        if seen != 3 {
            return TestResult::Fail("the shared mapping saw the wrong number of nodes");
        }
        if sum != 0x100 + 0x101 + 0x102 {
            return TestResult::Fail("the values userspace read are not the ones written");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bpf",
        smoke_bpf_arena_program_builds_list_walked_through_mapping
    );

    /// One base handle reaches two arenas in the same slot.
    ///
    /// Linux cannot do this — one arena per program, because its pointer is an
    /// absolute address. Here they are sub-ranges of one slot, so a single
    /// displacement from a single handle crosses from one into the other.
    fn smoke_bpf_arena_one_handle_reaches_two_arenas() -> TestResult {
        let cap = kernel_arena_cap();
        let mut g = match ArenaGroup::new(cap) {
            Ok(g) => g,
            Err(_) => return TestResult::Fail("ArenaGroup::new failed"),
        };
        let first = match g.add(cap, 1) {
            Ok(a) => a,
            Err(_) => return TestResult::Fail("adding the first arena failed"),
        };
        let second = match g.add(cap, 1) {
            Ok(a) => a,
            Err(_) => return TestResult::Fail("adding the second arena failed"),
        };
        if second.base_handle() != first.base_handle() + 4096 {
            return TestResult::Fail("the second arena is not adjacent to the first");
        }
        let group = Arc::new(g);

        // One `narf_arena_base()`, two stores: displacement 0 lands in the first
        // arena, 4096 in the second. Both are ordinary `off16` displacements.
        let insns = asm(&[
            call_arena_base(),
            st_imm(0, 0, 0x0A),
            st_imm(0, 4096, 0x0B),
            mov_imm(0, 1),
            Decoded::Exit,
        ]);
        let prog = match BpfProg::load_with_arena(
            load_cap(),
            request("two_arenas", insns),
            Some(Arc::clone(&group)),
        ) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("loading the two-arena program failed"),
        };
        if prog.run_atomic([0; 4], 4) != Some(Outcome::Returned(1)) {
            return TestResult::Fail("the two-arena program did not complete");
        }
        // Read each back through its *own* arena, which is what shows the two
        // stores did not both land in the first one.
        // SAFETY: both pages are populated and mapped RW for the arenas' lives.
        unsafe {
            if (first.kva() as *const u64).read_volatile() != 0x0A {
                return TestResult::Fail("the first arena did not receive its store");
            }
            if (second.kva() as *const u64).read_volatile() != 0x0B {
                return TestResult::Fail(
                    "a displacement past the first arena did not reach the second",
                );
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_arena_one_handle_reaches_two_arenas);

    /// A displacement past the end of the program's arenas traps diagnosably.
    ///
    /// The negative half of the two above, and the one that pins the runtime
    /// bound specifically: the verifier *accepts* this program, because it bounds
    /// an arena displacement against a fixed window rather than against this
    /// program's extent. Remove [`resolve_in`]'s bound and only this test goes
    /// red.
    fn smoke_bpf_arena_displacement_past_the_end_traps() -> TestResult {
        let cap = kernel_arena_cap();
        let group = match ArenaGroup::with_one(cap, 1) {
            Ok(g) => Arc::new(g),
            Err(_) => return TestResult::Fail("ArenaGroup::with_one failed"),
        };
        // The arena is one page; 8192 is two pages past its base.
        let insns = asm(&[
            call_arena_base(),
            st_imm(0, 8192, 0xBAD),
            mov_imm(0, 1),
            Decoded::Exit,
        ]);
        let prog =
            match BpfProg::load_with_arena(load_cap(), request("arena_oob", insns), Some(group)) {
                Ok(p) => p,
                Err(_) => return TestResult::Fail(
                    "the verifier rejected the program, so this no longer tests the runtime bound",
                ),
            };
        match prog.run_atomic([0; 4], 4) {
            Some(Outcome::Trapped(Trap::ArenaOutOfBounds { handle, .. })) => {
                // The offending handle must be in the diagnostic, not inferred.
                if handle != ARENA_BASE_HANDLE + 8192 {
                    return TestResult::Fail("the trap named the wrong handle");
                }
                TestResult::Pass
            }
            Some(Outcome::Returned(_)) => {
                TestResult::Fail("a write past the end of the arena was allowed")
            }
            _ => TestResult::Fail("the out-of-bounds arena write trapped for the wrong reason"),
        }
    }
    kernel_test_in!("bpf", smoke_bpf_arena_displacement_past_the_end_traps);

    /// The same handle, in a program with no arena, reaches nothing.
    ///
    /// [`narf_arena_base`] returns one constant to every program, so this is the
    /// test that the constant means "my arena" rather than "arena 0 of whoever
    /// has one".
    fn smoke_bpf_arena_handle_without_an_arena_reaches_nothing() -> TestResult {
        let insns = asm(&[
            call_arena_base(),
            st_imm(0, 0, 0x11),
            mov_imm(0, 1),
            Decoded::Exit,
        ]);
        let prog = match BpfProg::load(load_cap(), request("no_arena", insns)) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("loading the no-arena program failed"),
        };
        match prog.run_atomic([0; 4], 4) {
            Some(Outcome::Trapped(Trap::BadAccess { .. })) => TestResult::Pass,
            Some(Outcome::Returned(_)) => {
                TestResult::Fail("a program with no arena wrote through an arena handle")
            }
            _ => TestResult::Fail("the no-arena write trapped for the wrong reason"),
        }
    }
    kernel_test_in!(
        "bpf",
        smoke_bpf_arena_handle_without_an_arena_reaches_nothing
    );

    /// Handle 0 and the rest of the slot's null guard resolve to nothing.
    ///
    /// Checked against the resolver rather than through a program, because the
    /// verifier rejects a negative displacement before the runtime ever sees it —
    /// which is the right layering, and is why this property needs a test of its
    /// own rather than riding on a program that cannot be written.
    fn smoke_bpf_arena_null_guard_resolves_to_nothing() -> TestResult {
        let cap = kernel_arena_cap();
        let group = match ArenaGroup::with_one(cap, 1) {
            Ok(g) => g,
            Err(_) => return TestResult::Fail("ArenaGroup::with_one failed"),
        };
        let arenas = group.arenas();
        if resolve_in(arenas, 0, 8).is_some() {
            return TestResult::Fail("handle 0 resolved — `None` in Option<ArenaPtr> is unsound");
        }
        for h in [1u64, 8, 4088] {
            if resolve_in(arenas, h, 8).is_some() {
                return TestResult::Fail("a handle inside the null guard resolved");
            }
        }
        // The first real byte does resolve, so the guard is a boundary and not a
        // blanket refusal.
        if resolve_in(arenas, ARENA_BASE_HANDLE, 8).is_none() {
            return TestResult::Fail("the arena's first byte did not resolve");
        }
        // Straddling the end is refused as a whole rather than truncated.
        if resolve_in(arenas, ARENA_BASE_HANDLE + 4096 - 4, 8).is_some() {
            return TestResult::Fail("an access straddling the arena's end resolved");
        }
        if resolve_in(arenas, ARENA_BASE_HANDLE + 4096 - 8, 8).is_none() {
            return TestResult::Fail("the arena's last doubleword did not resolve");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_arena_null_guard_resolves_to_nothing);

    /// An atomic add on arena memory is a real atomic, and the shared mapping
    /// sees it.
    fn smoke_bpf_arena_atomic_add_is_visible_in_the_mapping() -> TestResult {
        let cap = kernel_arena_cap();
        let group = match ArenaGroup::with_one(cap, 1) {
            Ok(g) => Arc::new(g),
            Err(_) => return TestResult::Fail("ArenaGroup::with_one failed"),
        };
        let arena = Arc::clone(&group.arenas()[0]);
        let insns = asm(&[
            call_arena_base(),
            mov_imm(1, 7),
            atomic_add(0, 1),
            atomic_add(0, 1),
            mov_imm(0, 1),
            Decoded::Exit,
        ]);
        let prog = match BpfProg::load_with_arena(
            load_cap(),
            request("arena_atomic", insns),
            Some(Arc::clone(&group)),
        ) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("loading the arena-atomic program failed"),
        };
        if prog.run_atomic([0; 4], 4) != Some(Outcome::Returned(1)) {
            return TestResult::Fail("the arena-atomic program did not complete");
        }
        let file = ArenaFile::new(arena);
        let frames = match file.mmap_frames(0, 4096) {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("mmap_frames refused the arena"),
        };
        let view = SharedMapping {
            frames,
            base_handle: ARENA_BASE_HANDLE,
        };
        match view.read_u64(ARENA_BASE_HANDLE) {
            Some(14) => TestResult::Pass,
            Some(_) => TestResult::Fail("the two atomic adds did not both land"),
            None => TestResult::Fail("the shared mapping could not read the counter"),
        }
    }
    kernel_test_in!("bpf", smoke_bpf_arena_atomic_add_is_visible_in_the_mapping);

    /// A misaligned arena atomic is refused rather than emulated.
    ///
    /// Emulating it would silently make the operation non-atomic with respect to
    /// the other side of the mapping, which is the one property the program asked
    /// for.
    fn smoke_bpf_arena_misaligned_atomic_is_refused() -> TestResult {
        let cap = kernel_arena_cap();
        let group = match ArenaGroup::with_one(cap, 1) {
            Ok(g) => Arc::new(g),
            Err(_) => return TestResult::Fail("ArenaGroup::with_one failed"),
        };
        let insns = asm(&[
            call_arena_base(),
            mov_imm(1, 1),
            atomic_add(4, 1),
            mov_imm(0, 1),
            Decoded::Exit,
        ]);
        let prog = match BpfProg::load_with_arena(
            load_cap(),
            request("arena_atomic_bad", insns),
            Some(group),
        ) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("loading the misaligned-atomic program failed"),
        };
        match prog.run_atomic([0; 4], 4) {
            Some(Outcome::Trapped(Trap::ArenaUnaligned { .. })) => TestResult::Pass,
            Some(Outcome::Returned(_)) => {
                TestResult::Fail("a misaligned arena atomic was performed anyway")
            }
            _ => TestResult::Fail("the misaligned arena atomic trapped for the wrong reason"),
        }
    }
    kernel_test_in!("bpf", smoke_bpf_arena_misaligned_atomic_is_refused);

    /// `mmap_frames` returns the right sub-range and refuses everything else.
    fn smoke_bpf_arena_mmap_frames_bounds() -> TestResult {
        let cap = kernel_arena_cap();
        let group = match ArenaGroup::with_one(cap, 3) {
            Ok(g) => g,
            Err(_) => return TestResult::Fail("ArenaGroup::with_one failed"),
        };
        let file = ArenaFile::new(Arc::clone(&group.arenas()[0]));
        let all = match file.mmap_frames(0, 3 * 4096) {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("mmap_frames refused the whole arena"),
        };
        if all.len() != 3 {
            return TestResult::Fail("mmap_frames returned the wrong frame count");
        }
        // A sub-range must be the matching slice of the whole, or a partial
        // mapping shows userspace the wrong pages.
        match file.mmap_frames(4096, 4096) {
            Ok(one) if one.len() == 1 && one[0] == all[1] => {}
            Ok(_) => return TestResult::Fail("a sub-range did not match the whole"),
            Err(_) => return TestResult::Fail("mmap_frames refused a valid sub-range"),
        }
        // Past the end, misaligned, and empty are refused rather than clamped —
        // clamping would hand userspace a mapping of a different length than it
        // asked for, which the syscall layer treats as a contract violation.
        if file.mmap_frames(0, 4 * 4096).is_ok() {
            return TestResult::Fail("mmap_frames mapped past the end of the arena");
        }
        if file.mmap_frames(3 * 4096, 4096).is_ok() {
            return TestResult::Fail("mmap_frames mapped starting past the end");
        }
        if file.mmap_frames(1, 4096).is_ok() {
            return TestResult::Fail("mmap_frames accepted a misaligned offset");
        }
        if file.mmap_frames(0, 0).is_ok() {
            return TestResult::Fail("mmap_frames accepted an empty range");
        }
        if file.stat().size != 3 * 4096 {
            return TestResult::Fail("stat does not report the mappable extent");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_arena_mmap_frames_bounds);

    /// A revoked `Cap<BpfArena, Grant>` can neither reserve a slot nor grow a
    /// group it already handed out.
    fn smoke_bpf_arena_revoked_cap_cannot_create_a_group() -> TestResult {
        let cap = ArenaCap::bootstrap();
        let mut group = match ArenaGroup::new(&cap) {
            Ok(g) => g,
            Err(_) => return TestResult::Fail("ArenaGroup::new failed with a live cap"),
        };
        cap.revoke();
        match ArenaGroup::new(&cap) {
            Err(ArenaError::CapRevoked) => {}
            Ok(_) => return TestResult::Fail("a revoked cap still reserved a slot"),
            Err(_) => return TestResult::Fail("slot reservation failed for the wrong reason"),
        }
        // And on the group it already had: holding the group is not authority to
        // grow it.
        match group.add(&cap, 1) {
            Err(ArenaError::CapRevoked) => TestResult::Pass,
            Ok(_) => TestResult::Fail("a revoked cap still added an arena to an existing group"),
            Err(_) => TestResult::Fail("adding with a revoked cap failed for the wrong reason"),
        }
    }
    kernel_test_in!("bpf", smoke_bpf_arena_revoked_cap_cannot_create_a_group);

    /// An address-space cast on an arena handle is the identity.
    ///
    /// This is half of spec §8.1's "truncation sequence" question answered: there
    /// is no sequence, because a base-relative handle has the same value in both
    /// spaces. `Skip` rather than `Fail` when the verifier refuses the store, and
    /// the reason is recorded rather than asserted away: the verifier drops the
    /// offset's precision across a cast, so a store through the result may not be
    /// provable. If that changes, the interpreter half below starts running.
    fn smoke_bpf_arena_addr_space_cast_is_the_identity() -> TestResult {
        let cap = kernel_arena_cap();
        let group = match ArenaGroup::with_one(cap, 1) {
            Ok(g) => Arc::new(g),
            Err(_) => return TestResult::Fail("ArenaGroup::with_one failed"),
        };
        let arena = Arc::clone(&group.arenas()[0]);
        let insns = asm(&[
            call_arena_base(),
            // arena space (1) -> kernel space (0), then back.
            Decoded::AddrSpaceCast {
                dst: r(6),
                src: r(0),
                dst_as: 0,
                src_as: 1,
            },
            Decoded::AddrSpaceCast {
                dst: r(7),
                src: r(6),
                dst_as: 1,
                src_as: 0,
            },
            st_imm(7, 0, 0x5A),
            mov_imm(0, 1),
            Decoded::Exit,
        ]);
        let prog =
            match BpfProg::load_with_arena(load_cap(), request("arena_cast", insns), Some(group)) {
                Ok(p) => p,
                // Only *this* rejection is expected, and it is named rather than
                // shrugged at: the verifier replaces the offset with `UNKNOWN`
                // across a cast, so the store afterwards cannot be proved inside
                // the window. Any other error means the program is wrong for a
                // reason this test is not about, and skipping on it would hide it.
                Err(LoadError::Rejected(VerifyError::ArenaOutOfWindow { .. })) => {
                    return TestResult::Skip(
                        "verifier: an arena offset is UNKNOWN across an address-space cast",
                    )
                }
                Err(_) => {
                    return TestResult::Fail(
                        "the cast program failed to load for an unexpected reason",
                    )
                }
            };
        if prog.run_atomic([0; 4], 4) != Some(Outcome::Returned(1)) {
            return TestResult::Fail("the cast program did not complete");
        }
        // SAFETY: populated and mapped RW for the arena's life.
        if unsafe { (arena.kva() as *const u64).read_volatile() } != 0x5A {
            return TestResult::Fail("a round-tripped handle did not reach the arena");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpf_arena_addr_space_cast_is_the_identity);
}
