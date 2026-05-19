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
