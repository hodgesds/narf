# NARF documentation

Start with the guide that matches the job at hand:

- [Developer guide](DEVELOPER_GUIDE.md) — toolchain setup, builds, tests,
  workspace navigation, subsystem changes, drivers, and modules.
- [Administrator guide](ADMINISTRATOR_GUIDE.md) — images, QEMU and physical
  boot, operating limits, storage/network basics, and runtime modules.
- [Running on Linux](RUNNING_ON_LINUX.md) — detailed workstation and QEMU
  walkthrough.
- [Build personalities](PERSONAS.md) — `linux-compat`, container, and cgroup
  feature composition.
- [Extension guide](extending/README.md) — public traits and registration
  seams for subsystems and drivers.
- [Runtime modules](extending/modules.md) — built-in/loadable dual builds,
  manifests, signing, loading, and isolation-domain selection.
- [Pluggability](PLUGGABILITY.md) — capability-gated policy replacement; this
  is distinct from loading a new binary module.
- [Testing](../TESTING.md) and [current status](../STATUS.md) — authoritative
  verification commands and milestone state.

Subsystem contracts live beside their implementations in
`<subsystem>/specification/spec.md`. Those specifications, the current source,
and [STATUS.md](../STATUS.md) are authoritative. Historical design records and
point-in-time audits remain available through Git history rather than the live
documentation tree.
