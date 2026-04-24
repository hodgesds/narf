# drivers — Driver Framework + Drivers

The driver framework (lifecycle, domain binding, capability bootstrap)
plus the in-tree driver specs.

- Framework spec: [`specification/spec.md`](./specification/spec.md)
- Framework research: [`research/README.md`](./research/README.md)
- Stage: **Stage 3 framework landed.** `Driver` trait (async lifecycle
  via `Pin<Box<dyn Future>>`), `DriverHandle` cap marker →
  `CapKind::Driver`, `DriverManifest` (typed `CapKind` slice, not
  string list), `DomainPolicy::{Shared, Dedicated}`, `DriverEnv`,
  `DriverRegistry` with cap-gated `register()` returning a fresh
  per-driver `Cap<DriverHandle, Write>`, `DriverPhase` state machine
  providing shared exclusivity for `start_named`/`quiesce_named`,
  `with_entry` observer accessor, `NoopDriver` reference impl,
  `bootstrap_authority()`. Deferred to Stage 4: `#[driver(...)]`
  proc-macro + TOML manifest parser, panic containment (needs `frame/`
  trap-prologue cooperation), manifest signing (`crypto/`), unregister
  path, IRQ binding + MMIO region mapping in `DriverEnv`, multi-driver
  hot-reload.
- Per-driver subfolders:
  - [`virtio/`](./virtio/) — Stage 3 skeleton landed; full Stage 4.
  - [`nvme/`](./nvme/)
  - [`net/`](./net/)
  - [`gpu/`](./gpu/)
