# drivers — Research (framework)

## Primary sources

- **Fuchsia Driver Framework v2 (DFv2)** — modern isolation-first driver
  model. <https://fuchsia.dev/fuchsia-src/concepts/drivers/driver_framework>
- **seL4 device drivers model** — user-mode drivers communicating via
  endpoints. <https://docs.sel4.systems/Tutorials/devicedrivers.html>

## Secondary sources

- **Hubris tasks** — a minimal Rust driver-per-task model.
  <https://github.com/oxidecomputer/hubris>
- **Redox driver model** — drivers as user processes using schemes.
- **Linux driver model docs** — classic reference even though NARF diverges heavily.
- **Shiva — Programmable Runtime Linker (elfmaster/shiva)** — ELF
  "microprogram" injection, dynamic relocation engine, PLT hooking.
  Relevant framing: a driver in NARF is a position-independent ELF
  module loaded into its own PKS/MTE domain, with relocations resolved
  at load time and capability bootstrap via a custom interpreter.
  <https://github.com/elfmaster/shiva>

## Distilled summaries

- (None at framework level; per-driver summaries live in the driver
  subfolders.)

## Fetched this round

- `summaries/fuchsia-dfv2.md` — Fuchsia DFv2 architecture
- `summaries/sel4-device-drivers.md` — seL4 user-mode driver model

## Open research questions

- How closely does the manifest resemble DFv2 component manifests?
- Sandboxing WASM drivers — interesting future direction, not Stage 1–4.
