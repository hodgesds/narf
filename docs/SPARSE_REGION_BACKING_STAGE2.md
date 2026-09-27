# Sparse Region backing: Stage 2

Branch: `perf/sparse-region-backing-stage2`, based on main `5364c985`.
Prerequisite: PR #484 / `3a403581`, already merged by the user.
Classification: TCB / interface. Security review remains with the user.
Agent: OpenAI Codex, GPT-6 (no finer model version exposed in this session).
Unsigned commits are explicitly authorized below.

## Change

`Region.phys` now uses a sorted directory of 64-slot backing blocks. Logical
prefix length remains separate from allocated storage, preserving admission
and lazy-zero behavior. Reads in absent blocks return zero. A demand fault
reserves one block before entering an allocator or filesystem; publication
and mutable indexing never allocate. Lookup is logarithmic in block count;
sequential insertion is amortized, while insertion before existing blocks
shifts directory entries. No timing improvement is claimed.

Fork, fragment copies, relocation, ownership walks, reclaim scanning, and
page-table operations retain explicit virtual page offsets while skipping
missing blocks. Clone/drop affect metadata only. Existing COW, shared-owner,
reverse-map, and TLB-before-release responsibilities stay in AddressSpace.
Backing windows retain reserved zero slots for swap and outstanding claims.

The large ELF smoke now asserts that two faults separated by 4 GiB consume
at most 128 slots. The observed slot payload is 1,024 bytes, versus the
prerequisite's 8,388,616 bytes. Slot payload excludes directory keys and spare
capacity; `RegionBacking::metadata_bytes` exposes that retained heap payload.
These are representation counters, not timing benchmark results.

## Validation

- Dense-wrapper checkpoint: x86_64 921 pass / 0 fail / 7 skip;
  aarch64 684 pass / 0 fail / 7 skip. Both boot smokes passed.
- Sparse checkpoint: x86_64 415 pass / 0 fail / 12 skip, including
  distant-first fault, fork/COW, unaligned split, relocation, and discard.
- Pure backing tests: dense-reference model and distant/split/failure tests pass
  on the host, using the production backing and address modules.
- Release and debug builds pass on x86_64 and aarch64.
- Clippy with `-D warnings` passes on both architectures for boot-smoke,
  boot-smoke/container, user-mode-e2e, and kernel-test/cgroup/container.
- `cargo xtask host-test`: 554 passed, 0 failed, 2 ignored doctests.
- Full aarch64 kernel suite with `cgroup-all,container`: 6,770 passed,
  0 failed, 41 skipped. Boot smoke and btrfs write interop passed.
- User-mode gate (`user-mode-e2e`, `verification,userspace`): aarch64
  392 passed / 0 failed / 3 skipped; x86_64 568 passed / 0 failed / 3 skipped.
- x86_64 kernel sweep excluding `modules/e2e`, in two bounded filters:
  5,062 passed / 0 failed / 69 skipped and 3,748 passed / 0 failed / 15 skipped
  (8,810 passed / 0 failed / 84 skipped total). Both boot smokes and btrfs
  write-interop checks passed. The first partition explicitly passed all three
  new sparse tests; the second printed the 128-slot ELF result.
- Final `cargo fmt --all -- --check` and `git diff --check` pass. Safety TOML
  parses, all referenced invariant lines resolve, and the prompt hash matches.
- The unfiltered x86_64 suite reaches a module unload/reload page fault in
  `smoke_module_load_real_ko_round_trip`. The same isolated `modules/e2e`
  test faults on unchanged main `5364c985`, at the same module instruction
  offset (`+0x30`). The remaining x86_64 sweep excludes only `modules/e2e`;
  this baseline failure prevents claiming an all-green unfiltered suite.
  Baseline reproduction: `cargo xtask test --arch=x86_64 --features
  cgroup-all,container --subsystem modules/e2e` from a clean archive of main,
  with the same toolchain and `NARF_QEMU_MEM_MB=2048`.
- Optional musl-demo fixtures are unavailable (`musl-gcc` is not installed);
  the reported skip counts remain part of the results.
- Human security review: pending. No automated security-review pass is claimed.

The sandbox denied the host timeout runner's process notification after the
initial kernels completed; QEMU checkpoints were rerun outside the sandbox.

The two x86_64 partition filters (each below the boot command-line limit) are:

```text
aarch64,abi,accel,acpi,aml,arch,audio,block,bluetooth,boot,bpf,bus,capabilities,crypto,drivers,drivers-gpio,drivers-i2c,drivers-platform,drivers-platform-fan,edid,efi,event_bus,fb,filesystem,firmware,frame,graphics,hid,i3c,init,initramfs,input,interrupts,io,ipc,lib,memory,modules/compat,modules/deps,modules/domain,modules/elf,modules/kabi
modules/lifecycle,modules/manifest,modules/params,modules/plt,modules/procfs,modules/reloc,modules/sign,modules/symbols,modules/sysfs,narf-net,net,observability,pinctrl,pmbus,power,procsys_e2e,pwm,rcu,scheduler,scmi,security,shmem,spdm,subsystem,syscall_abi,sysfs_e2e,tag,time,tpm,tracing,uevent_e2e,usbpd,userspace,verification,wireless
```

Run each with `cargo xtask test --arch=x86_64 --features cgroup-all,container
--subsystem <filter>`. An earlier oversized-filter run and a run using stale
baseline artifacts were discarded; the final results above follow an explicit
release-profile memory-cache clean and verify the new test names/counters.

## Originating prompt

SHA-256 of the following text (without an added trailing newline): `313140fbb2960353e454ab43dfa4f5ebd5fd251f0d46506b7279dc6a07a4e076`.

```text
Summary of where things stand:

  perf/sparse-region-backing @ 3a403581 — one commit, clean tree, all gates green on both arches. It's the prerequisite for the sparse-backing work plus the measurement that makes the cost
  visible (backing_slots=1048577, slot_bytes=8388616 for two touched pages), not the fix itself.

  Stage 2 remains: swapping the dense Vec<PhysAddr> for a block-indexed map so metadata tracks touched pages rather than the highest offset. ~307 read sites and ~450 construction sites,
  compiler-enumerated once the field's type changes. Worth its own branch, with the suites run between mechanical steps — three of today's slips in this subsystem came from regex-driven edits,
  and the one that mattered (a helper rewritten into infinite recursion) was caught only because it happened to be a hard error rather than a lint.
```

Subsequent user instructions, in order:

> I merged perf/sparse-region-backing
>
> but lets make a new branch off main
>
> and finish everything
>
> continue
>
> I'll do the security review at the end and you can make unsigned commits
