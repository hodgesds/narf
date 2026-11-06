# drivers/gpu/tools/atom-trace — ATOM VBIOS command-table tracer

`atom-trace` is a host-side harness that executes a VBIOS command table
through NARF's ATOM interpreter (`drivers/gpu/src/amdgpu_atom_vm.rs`,
included verbatim) against a recording fake register bus, as
`amdgpu_atom_asic_init` would on the card, and reports every opcode,
table, IIO port, and register used. It is a standalone tool, not a
kernel workspace member.

```
cargo run --release --manifest-path drivers/gpu/tools/atom-trace/Cargo.toml -- navi22.rom
```

Usage: `atom-trace <vbios.rom> [--table N] [--set REG=VALUE]...
[--trace] [--max-steps N]` (ASIC_Init by default). The fake bus returns
the last value written to a register (0, or a `--set` value, before
that), so polling loops on hardware status bits spin until the
interpreter's 20 s same-jump guard fires on the fake clock; the report
names the table, offset, and registers polled, and `--set` can preload
the expected status to continue past them. The implementation is
`src/main.rs`.

- Interpreter: [`../../src/amdgpu_atom_vm.rs`](../../src/amdgpu_atom_vm.rs)
