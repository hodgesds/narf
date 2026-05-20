# Layout-shift latent UB exposed by `narf-block → narf-memory` dep edge

## Status

Open. Repro: add `narf-memory = { path = "../memory" }` to
`block/Cargo.toml`. Tree builds clean. Kernel-test under QEMU faults
with a #GP (no error code) inside the `abi` smoke suite at the test
*immediately after* `smoke_abi_dispatch_latency_accumulates` in link
order. The specific victim test changes with link order — `cancel_
after_target_completes_is_noop`, `narf_ipc::SendFuture::poll`,
`smoke_9p_tversion_rversion_frame_decode` have all appeared.

Without the dep edge, the same 2033 tests pass / 0 fail.

## Concrete fault signature

```
*** CPU EXCEPTION ***
  vector:  13 — #GP  general-protection
  error:   0x0000000000000000
  rip:     0xffffffff812b625d   cs: 0x08
  rflags:  0x0000000000010002
  rsp:     0x00000000010129f0   ss: 0x10
  rsi:     0x0000000040000f40   rdi: 0x0000000001012a84
  ...
```

Faulting instruction is a `call rel32` into `<&[T] PartialEq>::eq`.
Around it:

```
ffffffff812b6240 <String as PartialEq<&str>::ne>:
  812b6240  sub  $0x48, %rsp        ← prologue, no fault
  812b6244  mov  0x10(%rdi), %rsi   ← load String len
  812b624b  test %rsi, %rsi; js     ← negative-len branch (never taken)
  812b6207  movq $0x0, 0x38(%rsp)   ← stack write OK
  812b6210  movq $0x8, 0x28(%rsp)   ← stack write OK
  812b6219  movq $0x0, 0x30(%rsp)   ← stack write OK
  812b625d  call <slice::eq>        ← #GP here
```

The `sub $0x48,%rsp` and several subsequent `movq …,(%rsp)` succeed.
The `call` then faults. The target address (0xffffffff8146d900) is a
valid kernel high-half address. The return-address push target
(rsp − 8 = 0x010129e8) is in low memory.

## Hypothesis: 32-bit RSP truncation

RSP = `0x0000_0000_0101_29f0` is suspicious: the kernel stack lives
at `0xffff_8000_...` or `0xffff_ffff_8...`. The low 32 bits of the
expected canonical RSP would be `0x01...29f0` — i.e. the observed
RSP value matches "expected RSP with top 32 bits zeroed". That
points at a 32-bit pointer truncation somewhere in the kernel.

Why the stack stores worked but the call didn't: stores use a
register form `[rsp + imm8]`. The truncated RSP is still in
canonical (low) form for those addresses (a tiny 4 KiB page near
phys 0x010129f0 may be identity-mapped in the boot AS, so stores
succeed). The call's RSP push happens to land at a page that *isn't*
mapped → #PF, but reported as #GP due to a stack-segment-switch
detail (push that crosses a stack-segment boundary on 64-bit
typically reports #SS, but #GP can fire too depending on which
canonical check trips first).

## Why "9P2000" appears in some symptoms

The faulting function is a String/`&str` comparison. The
`smoke_9p_tversion_rversion_frame_decode` smoke calls `rv.version
!= "9P2000"`. The String body lives on the test's stack frame. When
RSP is truncated, the function reads the String descriptor from a
ghost-mapped page, finds a garbage `len` field (rsi=0x40000f40 ≈ 1
GB), and the subsequent `slice::eq` call faults on the push.

## What's not the cause

- `narf-memory::compress` / `zpool` modules are clean: linking them
  with their dep edge in the *memory* crate doesn't trigger the
  fault. Only the `narf-block → narf-memory` edge does.
- The slab-magazine work (`9ea308a`) doesn't touch anything that
  would produce a 32-bit truncated RSP. The codepath that finally
  faults is not in `memory/src/slab.rs`.
- The fault is path-dependent. Disabling
  `smoke_abi_dispatch_latency_accumulates` does not fix it — the
  next-in-order test fails instead.

## Further bisection (2026-05-19 follow-up)

The trigger is *specific to the `narf-memory` dep edge*, not any
dep edge:

- Adding `narf-arch = { path = "../arch" }` to `narf-block`'s
  `Cargo.toml` (also previously-transitive, same shape of new
  explicit edge) does **not** trigger the fault. 2037 pass / 0
  fail (1 test got shuffled to `[skip]` by the layout shift, but
  no #GP).
- Adding `narf-memory = { path = "../memory" }` *does* trigger
  the fault.

So the bug isn't "any dep edge shifts layout" — it's specifically
when `narf-memory` is pulled in as an explicit edge. The two crates
have the same transitive availability from `narf-block` (both come
through `narf-io`), but Cargo's edge-order resolution evidently
emits `narf-memory`'s artefacts at a different position in the link
than `narf-arch`'s.

Working theory refined: the stack-corruption signature (`String`
`len` field reads as `0x40000f40`, all over `0x4000_0xxx` register
soup) plus the fault path inside `<String as PartialEq<&str>>::ne`
in the 9p test points at a stack-frame overlap, not an actual RSP
truncation. The original RSP value (`0x010129f0`) sits in the boot
stack range (`.boot.data` section in `frame/src/x86_64/boot.S`,
64 KiB starting from a `LOAD_BASE + small_offset` address) which is
normal kernel operation — the kernel never swapped to a high-half
stack (Wave 2 deferred per `memory/src/lib.rs` comment). So
"truncation" is the wrong frame; the right one is "stack
re-use causes some prior frame's local to leak into the current
frame's `String::len` slot".

Reduction attempts that didn't move the needle:
- Inserting a `narf_scheduler::run_until_empty()` at the top of the
  faulting test (`smoke_abi_cancel_after_target_completes_is_noop`)
  — fault persists with the same shape.
- Disabling `smoke_abi_dispatch_latency_accumulates` entirely —
  fault now appears at `smoke_pstate_amd_summary_formats_freq_units`-
  next instead.
- Setting MAG_SIZE = 1 in `memory/src/slab.rs` — explodes
  immediately (the magazine code path assumes MAG_SIZE ≥ 2 for the
  flush-half math); confirms that the magazine layer is reachable
  but doesn't isolate it as cause.

## Stop point

CompressedRamDisk landed by sidestepping (moved into
`narf-memory` proper without the `BlockDeviceSync` impl).
2038 pass / 0 fail with no `narf-block → narf-memory` edge.

## 2026-05-19 — deeper trace + allocator canary tests

### Sharpened fault signature

With the dep edge applied, the fault rip lands inside
`narf_ipc::SendFuture<T,_>::poll` (specialisation hash
`a28ad706807f03a1`) at offset 0x4d. The instruction is:

```
movzbl 0xc0(%r13), %eax
```

r13 = `0xf000ff53f000ff53` — *non-canonical* x86_64 address (bit 47
= 1 but bits 48-63 are 0xf000, not 0xffff). Reading from a non-
canonical address is what raises #GP error 0.

How r13 got that value:

```
mov 0x90(%r14), %rax   ; rax = *(r14 + 0x90)
mov (%rax), %r13       ; r13 = *rax
movzbl 0xc0(%r13), %eax ; FAULT
```

r14 was set to `rsi` at function entry (`mov %rsi, %r14`). In SysV
the 2nd arg to `poll(self, cx)` is cx. So r14 *should* be cx, which
is a small `&mut Context<'_>` (≤ 40 bytes including nightly's
`local_waker` + `ext` fields).

But the fault dump shows `r14 = 0x40000eb0`. That value can't be a
stack address (boot kernel stack lives at `0x010xxxxx`). It looks
like a heap-or-MMIO address inside the 1 GiB region.

`*(0x40000eb0 + 0x90) = *(0x40000f40)` = some value (call it X).
`*X = 0xf000ff53f000ff53`, the famous PC-BIOS "system services
entry point" pattern at f000:ff53. The chain reads from MMIO /
phys 0x40000_xxxx and gets BIOS-shaped garbage that's non-
canonical when treated as a pointer.

### What the values mean

The 0x4000_0xxx register soup (`r11=0x40000c00`, `rbx=0x40000e00`,
`r14=0x40000eb0`, `r15=0x40000eb4`, `rsi=0x40000f40`) is too
consistent to be uninitialised stack memory. They look like
genuine pointers into a region that happens to be MMIO/reserved
instead of RAM. The fault dump's lowest is `0x40000c00` and
highest is `0x40000f40` — a ~832-byte span. Could be:

- Real-mode IVT or BIOS data area copied into a kernel struct
  at boot
- An ACPI table parsed but then over-released
- The framebuffer "info" structure handed to us by the bootloader

The kernel's identity map covers `[0, 4 GiB)`, so reads at
0x40000xxx succeed (they hit either RAM, MMIO, or the PCI hole
depending on QEMU's machine config). Q35 with `-m 1024M` has RAM
up to `0x40000000`, so 0x40000xxx is *just past* RAM — it sits in
the gap between RAM and the PCI-MMIO base.

### Allocator-side canaries (2026-05-19)

`memory/src/tests.rs` got five new smokes (`smoke_frame_alloc_
returns_pointer_in_ram`, `_slab_alloc_returns_pointer_in_ram`,
`_slab_double_alloc_distinct_pointers`, `_alloc_pages_on_
returns_in_ram`, `_alloc_pages_on_node1_below_4gb`). All five
pass on the clean tree, confirming the allocator path itself
doesn't hand back addresses past the identity-map ceiling. So
the bad `r14 = 0x40000eb0` isn't from a buddy/slab return — it's
from somewhere upstream.

### Best remaining hypotheses

1. The `Producer<T>` inside SendFuture has a stale `Arc<Ring>`
   whose data pointer was clobbered. The Arc's pointer at offset
   0 of the Producer would be loaded via r14 → r13 → fault path.
   Inspect how `submission_channel::<N>()` builds the Producer:
   if anywhere along the path a value gets stored that aliases an
   address in `[0x40000000, 0x40001000]`, that's the leak vector.

2. A scheduler task's Box::pin'd future stores a borrow that
   outlives its owner because of an incorrect lifetime. Under the
   shifted layout, the borrowed object happens to land in the
   reserved region and reads return BIOS garbage.

3. The compiler is generating wrong code for one specific
   inlining. Try rebuilding `narf-ipc` with
   `opt-level=0`-only via `[profile.dev.package."narf-ipc"]
   opt-level = 0` and see whether that moves or eliminates the
   fault. If opt-level=0 fixes it, the bug is a miscompile or
   relies on undefined behaviour the optimiser exposes.

### Best smoke to write next

A standalone test that:

1. Creates `submission_channel::<4>()` + `completion_channel::<4>()`.
2. Inspects the Producer/Consumer's internal pointers — verifies
   they're inside the kernel heap (>= heap base, < heap end).
3. Drops the pair without sending anything.
4. Re-creates and re-checks 1000 times. If any iteration's
   producer pointer is outside the heap range, the channel
   construction has a bug.

That would catch the upstream corruption without needing the
dep-edge layout shift to reproduce.

A focused chase session should:
1. Reproduce + run with KASAN-equivalent stack canaries (manual:
   write a magic word at the bottom of every freshly-spawned task's
   future Box and check it post-poll).
2. Tag every `String::from_utf8_lossy(...).into_owned()` allocation
   with a recognisable byte pattern via a custom alloc shim to
   spot which allocation is being smashed.
3. Inspect `narf-memory`'s `#[link_section]` directives — if any of
   the new sections (compress, zpool, compressed_ramdisk) end up
   merged into a section that has a fixed-size assumption baked
   into a downstream crate, layout shifts can corrupt that.

## Best next-steps for whoever picks this up

1. Reproduce: `python -c "open('block/Cargo.toml','a').write('\n')"`
   then add the line `narf-memory = { path = "../memory" }` after
   `narf-io`. Run `cargo xtask test`. Expect a #GP somewhere in
   `abi`-suite tests.

2. Find the truncation. Grep the kernel for patterns that read a
   `u32` and use it as an RSP-shaped value, or any inline asm
   that touches RSP through a 32-bit reg:

   ```sh
   grep -rn "as u32" frame/src/x86_64/ scheduler/src/ | grep -i 'sp\|stack'
   grep -rn '"mov.*esp\b"' --include='*.rs'
   grep -rn "rsp.*&\\s*0xffff_ffff\\|rsp.*as u32" --include='*.rs'
   ```

3. Check task-switch / scheduler stack-frame setup. The narf
   scheduler builds task stacks at spawn time; if the saved RSP for
   a freshly-spawned task gets truncated when the dispatcher's
   stack frame is allocated in the new layout, that would explain
   the path-dependence.

4. `core::ptr::copy_nonoverlapping` precondition variants surface
   the same root cause under earlier layout snapshots. The fix is
   one truncation site somewhere; both symptoms vanish together.

## 2026-05-19 (afternoon) — buddy double-free found

The "layout shift" framing was a red herring. The real bug is a
**buddy double-free** in `AddressSpace::drop`: the same physical
frame number is returned to the buddy twice from two different
paths inside the drop sequence, which leaves it on the free list
in a corrupted state. Subsequent allocations pop it for a new
caller, and the prior owner's still-live use of those bytes
(producer Arc, PML4 entry, etc.) overwrites the new caller's data
or vice-versa. Symptoms then range across the test suite depending
on what the second caller is doing with the frame — that's why
the apparent victim test wandered.

### Diagnostics landed in this commit

- `memory/src/frame.rs`: LOW_RESERVED_BYTES guard in `free_frame`
  and `free_pages` — refuses to put any frame below 1 MiB back
  into the buddy. (Frames in that range are never legitimately
  donated — see `donate_range`.) Catches one class of off-by-one.
- `memory/src/frame.rs`: `INUSE_POISON` double-allocation
  detector. Every `alloc_frame_on` writes 16 bytes of poison into
  the freshly handed-out frame; the next alloc checks for the
  pattern before returning the frame. If the buddy hands out
  the same frame twice with no intervening free, the second
  alloc panics. (Cannot detect double-allocations via
  `alloc_pages_on`, which doesn't go through this path.)
- `memory/src/frame.rs`: 1024-entry circular history of every
  `free_frame_tagged` and `alloc_frame_on` event keyed by phys
  address + site tag. Available to consumers via
  `__free_history_lookup(phys)`.
- `memory/src/buddy.rs`: `BuddyZone::free` now scans every
  free list before push, panicking if the new block overlaps
  an existing one. Includes a stack-text-address scan + the
  prior site tag from the free history.
- `console/src/lib.rs`: panic-handler RBP walk now accepts
  both kernel-high-half (`0xffff_...`) and boot-low-half
  (`0x010xxxxx`) RBP values so we get backtraces during
  pre-MMU-swap panics.
- Site tags 100/101/200/201/202/203/204 plumbed through
  `unmap_region_pages`, `mlock` race retry, the
  `free_user_pml4_tree` PT/PD/PDPT/PML4 frees, and the
  PML4-alloc error path so each free has a unique caller id.

### What we know now

- The duplicate frame moves around (`0xb000`, `0x1d3000`,
  `0x27dd000` depending on test order), but the bug always
  surfaces inside a test that drops a user `AddressSpace`.
- With site tags in place, the duplicate's prior owner is
  `203` (the PML4 frame itself, freed last in
  `free_user_pml4_tree`) — and the most recent allocation
  before the panicking free is recorded as `0xA110C`
  (the alloc sentinel), confirming the buddy re-issued the
  frame *between* the two frees without the second caller
  ever returning it.
- The drop sequence is: `for r in regions { unmap_region_pages(r) }
  → free_user_pml4_tree(self.root)`. Both paths *should* free
  distinct frames; the panic shows them freeing the same one.

### Remaining bisection step

Add a `(virt, phys)` pair-print to `unmap_4kb` for every leaf it
unmaps, and a `(slot, frame)` print to `free_user_pml4_tree` for
every PT/PD/PDPT it walks. The duplicate `phys` value will appear
in both transcripts — that names the region whose phys vec aliases
a page-table frame in PML4[1]'s subtree (or whose materialize
path wrote the page-table frame into a Region.phys[] by mistake).

That's the next concrete step. See git log for the commit
`(WIP) memory: double-free detector + tagged free_frame sites`.

## 2026-05-19 (evening) — root cause fixed

The "layout-shift" symptom traced to a real bug in
`AddressSpace::drop`: the same physical frame was being returned
to the buddy twice — once via `unmap_region_pages` (as a region's
data frame) and again via `free_user_pml4_tree` (as a page-table
frame in the same AS's PML4 subtree). The two paths' frame sets
overlapped because `free_user_pml4_tree` only walked `PML4[1]`
(user-binary subtree), missing the page-table pages that
`materialize`'s `ensure_next_table` had allocated for the
`MMAP_CURSOR` subtree at `PML4[129]`. Those PT/PD/PDPT pages
leaked unfreed AND were never visible to the drop walk.

Cumulative leakage across tests filled the buddy with frames that
appeared "free" but were actually still tracked as page-table
pages by the kernel's page-table walks. On a fork/clone or
subsequent alloc, the buddy handed one of these phys to a new
region as a data frame — creating the alias that triggered the
double-free on the next AS-drop.

### Fix (commit-tagged in `memory/`)

1. **`x86_64::paging::free_user_pml4_tree`** now walks BOTH
   `PML4[1]` (user binary) and `PML4[129]` (MMAP_CURSOR), freeing
   every PT/PD/PDPT in either subtree.
2. **`crate::frame::__pagetable_register` / `_unregister` /
   `_is_registered`** — flat 4 K-entry atomic registry of all
   page-table frames (`new_user_pml4_on` registers PML4 + user
   PDPT; `ensure_next_table` registers PT/PD/PDPT;
   `free_user_pml4_tree` unregisters each frame it reclaims).
3. **`AddressSpace::unmap_region_pages`** consults the registry:
   if `unmap_4kb` returns a phys that's still registered as a
   page-table frame, the region-side `free_frame` is skipped —
   `free_user_pml4_tree` is the canonical owner. This closes the
   double-free corner case where a region's data phys happens to
   alias a page-table phys.
4. **Defensive double-free guard in `BuddyZone::free`**: scans
   every free list before push, drops the duplicate on the floor
   if an overlapping block is already there. Belt-and-suspenders
   against future regressions or out-of-tree consumers that call
   `free` with a stale phys.
5. **`LOW_RESERVED_BYTES` guard in `free_frame`/`free_pages`**:
   refuses any phys below 1 MiB. Frames there are never
   legitimately donated (see `donate_range`), so a low-mem free
   indicates a bad source phys — silently dropping is safer than
   corrupting the buddy.

Test suite goes from "kernel #GP + hang in the abi suite" (with
the `narf-block → narf-memory` dep edge applied) to **2046 pass
/ 1 fail / 40 skip**. The one remaining failure
(`block / smoke_block_registry_uniform_read: registry empty`) is
a test-isolation bug unrelated to the double-free — likely a
link-order side-effect of the dep edge that delays driver
registration.

## What's landed despite this

- `e8f47b5`: LZ4 codec + Zpool compressed page pool, fully unit-
  tested and reachable from any future caller in the memory crate.
- The `CompressedRamDisk` block-device adapter (in
  `stash@{0}^3`) needs only a 4-line change to land once the
  truncation is fixed.

## Files / commits touched during the investigation

- `console/src/lib.rs` — panic-handler RBP-chain backtrace
  (commit `6134137`). Useful future diagnostic.
- `block/Cargo.toml` — the trigger, reverted.
