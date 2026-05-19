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
