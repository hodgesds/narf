# mte-enforcement — turning the aarch64 MTE domain backend on

> Status: **v0.2**. Steps 1 and 2 are implemented; nothing is enforced
> yet. This records what exists, what is missing, and the order the
> missing pieces have to land in, because getting that order wrong hangs
> the machine with no console.

## The problem

`effective_backend()` reports `Mte` on aarch64 and boot prints
`domain enforcer: mte`, but `Mte::enter_domain` is a structural no-op:
it returns `Self::save()` and never flips `SCTLR_EL1.TCF` from Ignore to
Sync, so a tag mismatch never faults. Nothing anywhere in the tree writes
TCF — a whole-tree search finds only comments.

An operator reading that line concludes driver domains are isolated on
aarch64. They are not. This is the same gap the x86 side had, where PCID
was selected while `CR4.PCIDE` was clear and `enter_domain` returned an
inert guard; that was closed by reporting `DomainBackend::Unenforced`
rather than naming an enforcer that enforces nothing.

Two ways to close it here. The cheap one is to select `Unenforced` on
aarch64 until enforcement lands — honest, small, and independent of
everything below. The real one is this document.

## What already exists

  * **Primitives.** `irg` (insert random tag), `stg` (store tag), `ldg`
    (load tag), `gmi` (tag-exclusion mask) in `arch/src/aarch64/mte.rs`,
    with smokes in `arch/src/tests.rs` and `ipc/src/tests.rs`.
  * **Detection.** `mte::supported()` reads `ID_AA64PFR1_EL1.MTE >= 1`.
    The test machine line already carries `mte=on`.
  * **State save/restore.** `SavedMteState` captures `SCTLR_EL1` (TCF
    mode + ATA) and `GCR_EL1`; `enter_domain`/`exit_domain` are wired
    into the `DomainPrimitive` shape and called from `bpf::domain::enter`.
  * **A Tagged Normal memory attribute.** `MAIR_EL1` Attr2 = `0xF0` and
    `PtFlags::ATTR_TAGGED` selects it. Until recently `ATTR_TAGGED`
    pointed at plain Normal WB, so a "tagged" mapping was never tagged.
  * **A tagged, tagged-up BPF arena.** Pages map `ATTR_TAGGED` and every
    granule carries the arena's tag. Nothing checks it yet.

## What is missing

1. **Tagged mappings.** No page anywhere is mapped with `ATTR_TAGGED`.
   MTE checks apply *only* to Tagged Normal memory, so with no tagged
   page there is nothing to check whatever TCF says.
2. **Tag storage.** Tagged memory needs a tag written per 16-byte
   granule (`stg`) before any tag-checked access, and pointers into it
   must carry the matching tag in bits 59:56.
3. **The TCF flip.** `enter_domain` must set TCF=Sync and
   `exit_domain` restore it.

## Why this cannot be done globally

Flipping TCF while tags are inconsistent faults on the *next* access.
The fault handler then runs, touches untagged kernel memory, faults
again, and the CPU loops with nothing on the console. `mte.rs` states
this hazard; it is the reason the no-op exists.

What makes it tractable: tag checking is a property of the *page*, not
the CPU. Untagged pages are never checked, even with TCF=Sync. So
enforcement can be scoped to a bounded region while the kernel stack,
text, and every other allocation stay unchecked — a mismatch then faults
on the intended access instead of bricking the CPU.

## Proposed increments

Each step is separately verifiable and leaves the tree working.

  1. **Map one bounded region tagged.** *Done.* The BPF arena:
     `map_arena_page` is a single chokepoint, the kernel controls every
     access, and the region is already isolated by design. Verified by
     `smoke_bpf_arena_pages_are_mapped_tagged`, which reads the leaf back
     and compares the whole AttrIndx field.
  2. **Tag on populate.** *Done.* `stg` writes the arena's tag to every
     granule after mapping, and `ArenaPage` carries a `tagged_kva`
     alongside the plain `kva`. Verified by
     `smoke_bpf_arena_pages_carry_a_tag`: `ldg` round-trips the tag, a
     mid-page granule carries it too, the tag is non-zero, and two pages
     carry the *same* tag.

     One tag per arena, not per page — see "The addressing contract".
     Tagging must follow mapping: the zeroing in `populate` goes through
     the untagged direct-map alias, and a store via a non-tagged alias
     may leave a location's tag UNKNOWN.
  3. **Make the arena's addressing contract tag-aware.** *Not started,
     and larger than it looks — see below.* This has to precede any TCF
     flip.
  4. **Flip TCF inside the domain scope.** `enter_domain` sets Sync,
     `exit_domain` restores. *Verify:* a deliberate tag mismatch inside
     the scope faults synchronously and is reported, and the existing
     arena smokes still pass.
  5. **Report honestly.** Only once the above hold does `Mte` deserve to
     be the reported enforcer. aarch64 reports `Unenforced` today, which
     was done first because it is independent of all of this.

## The addressing contract

This was underestimated when the increments above were first written,
and it is the reason step 3 exists.

Emitted code addresses the arena as `slot_base + handle + off16`, and
the JIT bounds-checks against
`[slot_base - ARENA_MAX_UNDERSHOOT_BYTES, slot_base + ARENA_SLOT_STRIDE)`
(`bpf/src/jit_glue.rs`). Every arena access therefore inherits one base
pointer's tag. Two consequences:

  * **Per-page tags cannot work.** A single `slot_base` tag cannot match
    pages tagged differently, so the check would fire on a legitimate
    access that merely crossed a page boundary. Hence one tag per arena.
    The isolation this buys is arena-vs-not-arena, not intra-arena.
  * **`slot_base` has to carry the tag, and that fights the bounds
    arithmetic.** With TCF=Sync, an untagged `slot_base` means every
    legitimate access arrives with tag 0 and faults. But the tag sits in
    bits 59:56, so a tagged base makes `a < lo || a >= hi` compare
    inflated values unless every bound carries the identical tag or the
    comparison strips it first.

So step 3 is "make the JIT's arena addressing contract tag-aware",
touching `jit_glue`, the emitter, and the bounds checks — not a bit flip
in `enter_domain`. Half-doing it produces exactly the failure this
document opens with: a fault the handler cannot service, and no console.

The open design question is where the tag is stripped. Candidates:
carry it in `slot_base` and mask in the bounds comparison; keep
`slot_base` plain and have the emitter OR the tag into the computed
address; or give the arena a fixed tag known at emit time. Each moves
the cost to a different place, and none is obviously right yet.

## Traps

  * **Attribute fields cannot be OR-ed.** `map_4kb` composes a leaf as
    `default | caller_flags`, which works only because `ATTR_NORMAL` is
    index 0 and contributes nothing to bits [4:2]. A caller that passes
    `ATTR_TAGGED` gets index 2 exactly; a caller that passes two
    attributes gets their bitwise OR, which is a different index. This
    already caused one wrong fix: relabelling the indices without
    reordering MAIR mapped every `ioremap` Device window cacheable, and
    the suites passed anyway because QEMU tolerates it.
  * **MAIR is per-CPU.** `boot.S` and `smp_entry.S` must program the
    same value or an AP reads different attributes from identical
    descriptors.
  * **Green suites are not evidence here.** Memory-attribute bugs stay
    invisible under QEMU: Device memory still reads and writes, and
    cacheable MMIO still works. Assertions have to read the leaf back.
  * **Tag checking needs the allocator's cooperation.** Any path that
    hands out an untagged pointer into a tagged page faults once TCF is
    Sync. Step 2 is where that surfaces, which is why it precedes 3.

## Open questions

  * **Granule cost.** `stg` per 16 bytes on populate is a measurable
    cost on a large arena; whether to tag lazily or per-page-on-first-use
    is unresolved.
  * **Scope beyond the arena.** Driver domains are the eventual target.
    Extending past the arena needs an MTE-aware slab, which is the
    "Stage-3 tag storage bring-up" `mte.rs` refers to.
  * **What a mismatch should do.** Sync faults give a precise address;
    async is cheaper. Sync is the right default for a first
    implementation.
