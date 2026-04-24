# Stage 3 Integration Guide

For the four agents working Stage 3 in parallel (one foreground on the
critical path; three background on `rcu/`, `bus/`, `tracing/` side
tracks). Read this before touching the tree.

## Crate conventions

Every NARF crate is `#![no_std]` and uses the same lint preamble. See
`scheduler/src/lib.rs` for a canonical example; mirror its shape.

- Crate root attributes, in this order:

  ```rust
  #![no_std]
  #![forbid(unsafe_op_in_unsafe_fn)]
  #![deny(missing_debug_implementations)]
  ```

- Crate-level `//!` doc-comment. First line: one-sentence summary.
  Second paragraph: `Spec: <crate>/specification/spec.md` with a
  reference to the relevant section/stage. Document non-goals as a
  bulleted list (copy the pattern from `scheduler/src/lib.rs`).
- `extern crate alloc;` only if the crate actually allocates; never
  pull in `std`.
- Every public type has `Debug`. When a field must not leak to
  formatting, implement `Debug` by hand with `.finish_non_exhaustive()`
  — the lint fails if you skip it. See the `TaskSlot::fmt` pattern in
  `scheduler/src/lib.rs`.
- Workspace lints (root `Cargo.toml` `[workspace.lints]`) apply
  automatically via `lints.workspace = true` in the crate's
  `Cargo.toml` — use that inherit line; do not restate the lints.
- `unsafe` rules: block-scope SAFETY comments are mandatory
  (`undocumented_unsafe_blocks` lint). Every privileged
  MSR/system-register access goes through the `arch/` HAL wrapper
  with its `compiler_fence(SeqCst)` pair — do not inline `asm!` for
  privileged ops in side-track crates.

Code style:

- No emojis anywhere in tracked files.
- Comments explain the *why* when the why is non-obvious. The *what*
  is the code; do not paraphrase it. See the long block comments in
  `scheduler/src/lib.rs` around `run_until_empty` for the tone.
- Keep `//` line comments; do not insert `/* … */` block comments in
  code unless you are writing an ASCII-art header (the `── foo ──`
  dividers in existing crates are `//`, not `/* */`).

## Workspace registration

The root `Cargo.toml` lists every crate as a workspace member.
Current members (read before editing):

```toml
members = [
    "lib",
    "arch",
    "boot",
    ...
    "build/xtask",
]
```

Adding a new crate — e.g. expanding `rcu/`, `bus/`, or `tracing/` —
means appending the folder name to that array.

**This is the primary merge-conflict point between side tracks.**
Three agents each adding their own `members = [ ... ]` line in
separate worktrees will conflict at merge. Resolution:

- Each side-track agent adds only their own member line. Do not
  reorder the list; append.
- If your crate did not exist as a workspace member before Stage 3
  (because it was a design-phase skeleton), adding it is the
  conflict. If it did (`rcu/`, `bus/`, `tracing/` may already be
  listed), you are editing code, not members — no conflict.
- Check with `rg '"<your-crate>"' Cargo.toml` before adding; the
  Stage 1 / Stage 2 waves may already have landed your member line.
- The foreground agent (or the human coordinator) resolves the
  final three-way merge onto `main` by union of the three lines.

## Test registration pattern

`verification/src/lib.rs` hosts the harness. Tests are registered via
the `kernel_test!` macro, which places a `KernelTest` struct in a
dedicated `narf.tests` ELF section. At runtime the harness walks from
`__narf_tests_start` to `__narf_tests_end` — linkme-style collector
without the linkme dependency.

- Every test has signature `fn() -> TestResult` (no args). Keep it
  pure; parallel execution arrives later.
- Write the test, then call `kernel_test!(my_smoke_test);` at module
  scope. Do not use a naming prefix beyond `smoke_` — that is the
  convention for Stage-N baseline tests.
- For arch-gated tests, wrap both the function and the macro call in
  `#[cfg(target_arch = "x86_64")]` (or aarch64). See
  `smoke_timer_irq_fires` in `verification/src/lib.rs`.
- Tests that need subsystem state (allocator, scheduler) must
  tolerate the "not yet initialised" case — return
  `TestResult::Skip("reason")` rather than failing. The harness runs
  before some subsystems are online depending on binary flavour.
- `cargo xtask test --arch=x86_64` and `cargo xtask test
  --arch=aarch64` build the test-harness flavour of the kernel, boot
  it under QEMU, and map the harness `exit_kernel(0|1)` to process
  exit codes via `isa-debug-exit`. Pass = 0, Fail = 1.

## Exit-gate check per side track

For any of `rcu/`, `bus/`, `tracing/`:

1. `cargo build -p narf-<crate> --target x86_64-unknown-none` and
   `--target aarch64-unknown-none` both succeed.
2. At least one new `kernel_test!(smoke_<crate>_<scenario>)` lands in
   `verification/src/lib.rs` exercising the crate under the running
   kernel.
3. `cargo xtask test --arch=x86_64` produces `Pass`.
4. `cargo xtask test --arch=aarch64` produces `Pass`.
5. `cargo clippy --all-targets -- -D warnings` clean on both arches.
6. `cargo fmt --check` clean.

All six are required. Partial credit is not a merge gate per
`AGENTS.md`.

## Scope discipline (side-track agents)

The side tracks do not touch the critical path. In particular, do
not modify any file under:

- `capabilities/`
- `ipc/`
- `abi/`
- `scheduler/`
- `frame/`
- `arch/`
- `memory/`

If your work needs a type or function from one of these, either:

- Stub it locally inside your crate behind a `pub(crate)` shim and
  flag it in your final report as a blocker for post-merge cleanup,
  or
- Use an existing Stage-1/Stage-2 public API — these crates already
  expose plenty. Check before stubbing.

You *may* edit:

- Your own crate's source.
- `verification/src/lib.rs` (add `kernel_test!` entries only; do not
  modify harness internals).
- Root `Cargo.toml` (append one workspace member line — see above).
- Linker scripts under `build/linker/*.ld` — but only for
  `tracing/` to add the `.note.narf.probes` output section, and only
  by adding new entries, not restructuring existing ones.

The foreground agent owns `capabilities/`, `ipc/`, `abi/`, and
`drivers/` for Stage 3. If you believe you need to touch one of them,
stop and flag it; the coordinator re-scopes the task rather than
allowing a cross-cutting edit.

## How to report back

Final message from each side-track agent to the main / coordinator
must contain, in order:

1. **Summary** (1–3 sentences): what landed, which spec sections it
   covers, whether the exit-gate check is green.
2. **Files touched** — absolute paths. Flag any entries under the
   scope-discipline block above (should be none except stubs called
   out explicitly).
3. **Test results** — the pass/fail counts from `cargo xtask test`
   on both arches. If a test was skipped, include the skip reason.
4. **Blockers / stubs** — every `todo!()`, `unimplemented!()`, or
   shim left behind, with one sentence on what would resolve it.
   This is the handoff checklist for the next wave.
5. **Workspace member line** — the exact line you appended to the
   root `Cargo.toml`, so the coordinator's merge is mechanical.

Keep the report under ~40 lines. The coordinator relays it to the
user; overlong reports get truncated.
