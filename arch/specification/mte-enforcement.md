# mte-enforcement — turning the aarch64 MTE domain backend on

> Status: **v0.7**. Steps 1–5 are implemented. MTE **is enforcing**, for
> the BPF arena and nothing else, and the boot report says exactly that:
> the backend stays `Unenforced` and the arena's tag checking is reported
> on its own line. This records what exists, what is missing, and the order the
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
  3. **Make the arena's addressing contract tag-aware.** *Done, and
     smaller than "see below" predicted — the prediction was wrong for a
     reason worth keeping; see "The addressing contract".* Emitted code
     receives `ArenaGroup::slot_base_tagged()`: the same VA carrying the
     arena's tag in bits 59:56. The emitter is untouched. Verified by
     `smoke_bpf_arena_slot_base_carries_the_arena_tag` (the base carries
     *this arena's* tag, and the untagged base does not),
     `smoke_bpf_arena_tagged_base_reaches_the_same_bytes` (TBI1 really is
     on, so the tagged base addresses the same memory),
     `smoke_bpf_arena_multi_arena_base_is_untagged` and
     `smoke_bpf_arena_untagged_platforms_get_a_plain_base`.

     Doing this surfaced a bug in step 2: the tagged pointer was built by
     OR-ing into a field that is already all ones on a TTBR1 address, so
     every arena's tag was 15 — the value every untagged kernel pointer
     carries. Fixed separately; see "What step 3 found".
  4. **Flip TCF inside the domain scope.** *Done.* `Mte::enter_domain`
     sets `SCTLR_EL1.TCF` to Sync, `exit_domain` restores the saved
     value, both followed by an `ISB`. Verified by
     `smoke_bpf_arena_untagged_access_faults_in_scope`: an untagged
     pointer into a tagged arena page faults inside the scope with
     DFSC `0b010001` (Synchronous Tag Check Fault), while the tagged
     pointer works inside it, the untagged pointer works outside it, and
     TCF is back to Ignore after the scope exits.

     The hazard the old no-op described — flip, fault, re-fault in the
     handler, loop with no console — rested on treating tag checking as a
     CPU-wide property. It is a property of the *page*: only
     `ATTR_TAGGED` pages are checked, and only the arena's are mapped that
     way, so the kernel stack, text, heap and page tables are unchecked
     whatever TCF says. The blast radius is exactly the arena.

     Two things had to be fixed first, neither of them in `enter_domain`:

       * **The interpreter addressed the arena untagged.**
         `ProgArena::resolve` returned `arena.kva() + off` and the
         interpreter dereferences it from inside the scope. This is worse
         than the JIT case: the EL1 abort handler's exception-table lookup
         is keyed on `ELR_EL1` with no DFSC gate, so a tag fault in JIT'd
         text recovers into the arena-fault epilogue and is *reported*,
         while an interpreter fault has no entry, falls past
         `probe::consume`, and is fatal. `resolve` now tags.
       * **`write_sctlr_el1` issues no `ISB`**, only compiler fences. A
         system-register write is not context-synchronising, so without one
         the first accesses after the flip run under the old mode.
  5. **Report honestly.** *Done — as a scope line, not a rename; see
     below.* The backend stays `DomainBackend::Unenforced`, because no
     enforcer is wired into module domain entry, and boot prints a second
     line stating that MTE tag checking is active for the BPF arena.
     Verified by `smoke_aarch64_report_matches_enforcement`, which asserts
     both halves: the report is `Unenforced`, and — on a CPU with MTE —
     `enter_domain` really does set TCF=Sync and `exit_domain` restores
     it.

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

Step 3 was scoped as "touching `jit_glue`, the emitter, and the bounds
checks". It touched none of them — see below for why the estimate was
wrong. Half-doing it would still produce the failure this document opens
with: a fault the handler cannot service, and no console.

The open design question was where the tag is stripped. It dissolved:
**there is no runtime bounds comparison to strip it from.** `arena.rs`
says so directly — a JIT "lowers this to `slot_base + handle + off16`
with no per-access check". The bound is structural, not compared: the
handle is zero-extended from a `W` register to `[0, 2^32)`, `off16` is at
most ±32 KiB, and the arena slot's unmapped guard slots absorb the rest.
The `[lo, hi)` range in this document is a *static* argument about
reachable addresses, not emitted instructions.

So the contract is one pointer. `ArenaGroup::slot_base_tagged()` carries
the arena's tag; `slot_base()` stays untagged for kernel arithmetic and
for the non-zero admission check. The emitter needs no change, because
neither a zero-extended 32-bit handle nor a ±32 KiB displacement can
disturb bits 59:56.

Three things had to hold, and were checked rather than assumed:

  * **TBI1 is on.** `boot.S:219` loads `0x62 << 32` — bits 33, 37, 38, so
    IPS=40-bit with TBI0 and TBI1 set. Without it a tagged base is
    non-canonical and every arena access faults immediately, not at the
    TCF flip. `smoke_bpf_arena_tagged_base_reaches_the_same_bytes` pins
    it, because a cleared TBI1 would otherwise surface as a boot hang.
  * **The fault epilogue reports `AHANDLE`**, which holds `handle + off`
    and never the base, so the offending-handle diagnostic is not
    inflated by the tag.
  * **The exception table keys on the faulting instruction's PC**, not on
    the data address, so a tagged pointer does not perturb lookup.

## What step 3 found

Step 2 tagged nothing. `tag_arena_page` built the tagged alias as
`kva | (tag << 56)`, and a TTBR1 address has bits 63:48 set, so the tag
field already read `0b1111` and the OR was a no-op. `stg` wrote 15 to
every granule, `pick_arena_tag`'s choice was discarded, and
`ArenaPage::tagged_kva` equalled `kva`.

Tag 15 is what every untagged kernel pointer carries, so the arena's tag
matched everything. `pick_arena_tag` had guarded against tag 0 — right
idea, wrong number: 0 is the untagged value for *user* pointers.

Nothing misbehaved, because nothing was enforcing. The hazard was step 4:
flipping TCF on top of this yields a backend that reports `Mte`, faults on
nothing, and passes its own smokes. That is the failure this document
opens with, arrived at from the other direction.

Two lessons worth carrying into steps 4 and 5. **The step-2 smoke passed
throughout** — it asserted `tag != 0` and that `tagged_kva` matched `kva`
outside the tag field, and "every tag is 15" satisfies both. An assertion
about tags has to name the value an *untagged kernel pointer* carries, not
zero. And **tag arithmetic belongs in one helper**: it was open-coded at
two sites and both were wrong identically. `mte::with_tag`, `tag_of` and
`UNTAGGED_KERNEL_TAG` now exist for that reason.

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

## Why step 5 is not just a rename

Steps 1–4 hold, so on the original plan `Mte` would now be the reported
enforcer. Reporting it would still overclaim, for a reason this document
did not anticipate.

The TCF flip is wired into `bpf::domain::enter` and nowhere else. Driver
domains are entered through `modules::domain::enter`, which gates on
`pks::is_active() || pcid::is_active()` — both false on aarch64 — so a
kernel module's `init()` and `exit()` run with no domain confinement at
all. What is enforced today is arena-vs-not-arena for BPF, which is what
`Arena::tag`'s own documentation says the tag buys. It is not
driver-domain isolation.

An operator reading `domain enforcer: mte` concludes driver domains are
isolated on aarch64. That is the same defect this document opens with,
and the same one the x86 side fixed by reporting `Unenforced` rather than
naming an enforcer that enforces nothing — reintroduced on the third
architecture, one step before the finish line.

**Resolved: keep `Unenforced`, report the scope.** Boot prints two lines
— that driver domains are not isolated because no enforcer is wired into
module domain entry, and that MTE tag checking is active for the BPF
arena. They are separate lines rather than one sentence because they
describe different scopes, and folding them together invites reading the
second as a qualifier on the first. A reader needs both: the first is what
they must not rely on, and without the second the `mte=on` in the feature
line directly above looks like dead configuration.

The alternative — extend the flip to `modules::domain::enter` and report
`Mte` — remains open. It needs its own access audit: module code touching
any tagged page inside its scope would begin to fault, and unlike BPF
there is no single chokepoint to tag, which is the same "cooperation from
the allocator" problem listed under Traps.

`smoke_aarch64_report_matches_enforcement` now pins the rule this document
has been about from the start — the reported name matches what is enforced
— and it is the first test in the tree to assert anything about
`effective_backend()` at all. That absence is why the mistake was made
three times: PCID selected with `CR4.PCIDE` clear, PKS and PCID documented
as equivalent, and this arm naming an enforcer twice over.

## Step 6 — driver domains: attempted, reverted, and what it needs

Extending enforcement from the BPF arena to driver domains was tried and
backed out. The page-level half works; the addressing half does not, and
the two cannot land separately. What follows is what was learned, so the
next attempt starts from here rather than from scratch.

### x86 is not the model to copy from, but it is real

`module_text::protection_key` is wired: `leaf_flags(domain)` ORs
`PtFlags::pk(D)` into every module leaf, and `alloc(pages, domain)` uses
it. PKS module isolation is genuine on x86. aarch64's `leaf_flags`
explicitly drops the domain — "the domain does not travel in the leaf
here" — so this is aarch64 catching up, not a tree-wide gap.

### What worked

Module pages can carry the domain: map them `ATTR_TAGGED` and have `alloc`
write the domain's tag to every granule after the trap-fill (the same
ordering `bpf_arena` needs — the fill goes through the untagged VA, and a
store via a non-tagged alias can leave a granule UNKNOWN). Two readback
tests were written and **passed**: one reading the leaf's whole `AttrIndx`
field and `ldg`-ing the tag back from byte 0 and a mid-page granule, one
asserting distinct tags per domain.

### The tag space is one short, and the obvious sacrifice is wrong

MTE has 16 tags, NARF has 16 domains, and tag 15 is what every untagged
kernel pointer reads as. So fifteen usable tags must cover sixteen domains
and exactly one domain goes untagged.

It must be `FRAME` (mapping `D` to `D - 1`). `FRAME` is the TCB, its
memory is not `ATTR_TAGGED` anyway, and `enter_domain` deliberately leaves
it reachable from everywhere, so "unprotected" describes what it already
is. The identity mapping — leaving domain 15 untagged — looks equivalent
and is not: `DomainId::SCRATCH` **is** 15. It is a real driver domain, it
is the one the module tests use, and sacrificing it made the only test
that verifies tagging *skip* rather than run. The mechanism looked
delivered and did nothing where it was most likely to be exercised.

### The blocker: the relocator has no addressing contract

For a module's own accesses to match its tagged granules, its code must
run at a tagged VA — then absolute relocations carry the tag and
`ADRP`-computed addresses inherit it from the PC. Relocating against
`ModuleImage::tagged_base()` does that, and breaks loading outright:
`smoke_module_load_real_ko_round_trip` fails with "sys_init_module
rejected a real rustc-built .ko".

`relocator.rs` computes `words = (target - place) >> 2` for
`R_AARCH64_CALL26` / `JUMP26`. `target` is a kernel symbol — untagged, so
tag 15 — while `place` is inside the image at tag `D - 1`. The difference
carries `(15 - (D - 1)) << 56`, every call overflows the ±128 MiB bound,
each demands a PLT veneer, the PLT exhausts, and the load is refused.

This is the question "The addressing contract" above asks, arriving for
real. For the JIT it dissolved because nothing compares addresses. The
relocator compares constantly, so the contract must be stated and applied:
**displacements are computed on untagged addresses; stored absolute
addresses carry the tag.** That is a change across `CALL26`/`JUMP26`,
`ADRP`/`ADD` and `PREL32` handling, and it is the real content of step 6 —
the page tagging is the easy part.

### Why the halves cannot land separately

Tagging module pages without the addressing contract is not a safe
intermediate. `TCF` is per-CPU and checks are per-page, so while any BPF
domain scope holds `TCF=Sync`, an interrupt into driver code that touches
its own now-tagged data through an untagged pointer takes a fatal fault —
there is no exception-table entry for module code. Page tagging and the
relocator contract must land together, or neither.

## Step 6 audit — every aarch64 relocation, and which ones the tag breaks

Scoping pass over `modules/src/elf/reloc.rs::apply_aarch64` and the
veneer pre-check in `modules/src/relocator.rs`. The question for each type
is what it does with `val` (the symbol address, `sym_value + addend`) and
`place` (`target_addr + loc`, always inside the module image). With the
image relocated against a tagged base, `place` carries tag `D-1` while a
kernel `val` carries the untagged 15.

The rule the whole table reduces to: **a displacement must be computed on
untagged operands; an absolute value must keep its tag.**

| Relocation | Computation | Tag participates? | Action |
|---|---|---|---|
| `ABS64` | writes `val` | yes, and correctly | none — this is how a module's absolute pointers acquire the tag |
| `ABS32` | `val`, errors if `> u32::MAX` | no | none — a 64-bit VA overflows tagged or not |
| `PREL64` | `val - place` | **yes** | untag both |
| `PREL32` | `val - place`, ±2 GiB | **yes** | untag both |
| `CALL26` / `JUMP26` | `(val - place) >> 2`, ±128 MiB | **yes** | untag both |
| `ADR_PREL_PG_HI21` | `(val&!0xFFF) - (place&!0xFFF) >> 12`, ±4 GiB | **yes** — masking 12 bits does not clear bit 56 | untag both |
| `ADD_ABS_LO12_NC` | `val & 0xFFF` | no | none |
| `LDST64_ABS_LO12_NC` | `val & 0xFFF` | no | none |
| `MOVW_UABS_G0..G2(_NC)` | `val >> lsb`, checked forms error `> 0xFFFF` | no — tag sits in G3 | none |
| `MOVW_UABS_G3` | `val >> 48` | yes, and correctly | none — this is how a MOVZ/MOVK-materialised pointer gets the tag |
| `NONE` | — | no | none |

So five arms change, out of eighteen. Plus one more site, and it is the
one that actually failed: `relocator.rs:188` duplicates the `CALL26` /
`JUMP26` range check to decide whether a PLT veneer is needed. Left
tagged, every call appears to overflow ±128 MiB, every call demands a
veneer, and the PLT exhausts — which is the "rejected a real rustc-built
.ko" that ended the first attempt.

### Why the absolute forms are right to leave alone

`ABS64` and `MOVW_UABS_G3` are not oversights to fix later — they are the
mechanism. An in-module symbol relocated absolutely yields a tagged
pointer, which is exactly what makes the module's own data accesses match
its granules. A kernel symbol yields an untagged one, which is also right:
kernel pages are `ATTR_NORMAL` and unchecked.

The same argument covers `ADRP` at *runtime*, which is worth stating
because it looks like a problem and is not. The relocation encodes a page
displacement computed untagged, but the CPU adds it to the live PC, which
is tagged because the module executes at a tagged VA. An in-module target
therefore resolves to a tag-`D-1` pointer (correct — matches the
granules), and a kernel target resolves to a kernel address that happens
to carry tag `D-1` (harmless — the page is not tagged, so nothing checks
it). No runtime change is needed for `ADRP`; only the link-time
displacement must be untagged.

### Beyond the relocator

`module_text::is_module_va` range-checks against `MODULE_VA_BASE` and
would reject a tagged PC, so anything attributing an address to a module —
backtraces, `/proc/modules`-adjacent diagnostics — needs to untag first.
Diagnostic-only, but it fails silently: a module frame simply stops being
recognised as one.

### Proven versus inferred

Only `CALL26` is demonstrated: it is what the failing load hit. The other
four are read off the arithmetic, and `PREL32`/`PREL64` in particular may
not appear in a real `.ko` at all — the existing comment in `reloc.rs`
notes that `MOVW_UABS` quartets were added only because a rustc-built
module used them where a synthesized test ELF did not. Before editing, log
the relocation types the reference module actually emits; a type that
never appears needs the fix for correctness but cannot be tested, and
should be marked as such rather than counted as covered.
