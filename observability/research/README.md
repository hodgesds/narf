# observability — Research

Scope narrowed: event-stream tracing research is in `tracing/research/`.
This folder covers perf counters, debugger integration, and crash /
post-mortem inspection.

## Primary sources

### Performance counters
- **Intel SDM Vol. 3B — Chapters 18–19 (Performance Monitoring)**.
  <https://www.intel.com/sdm>
- **ARMv8 PMUv3 specification** — part of Arm ARM (DDI 0487).
- **`perf_event_open(2)` + `tools/perf/`** — Linux's PMU-facing API;
  richest open implementation of multiplexing, group-leader
  semantics, and sampling.

### Debugger integration
- **GDB Remote Serial Protocol**.
  <https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html>
- **Intel SDM Vol. 3B — Chapter 17 (Debug, Branch Profile, TSC, Intel
  Resource Director Technology)** — debug registers.
- **Arm ARM — Debug and DebugMonitor** — D10 in DDI 0487.

### Crash / post-mortem
- **ELF core file format** — baseline for crash dumps.
  <https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html>
- **Linux `Documentation/admin-guide/kdump/kdump.rst`** — reference
  kdump flow.
- **`crash` utility** — SGI/RedHat crash dump analyser.
  <https://crash-utility.github.io/>

## Secondary sources

- **Brendan Gregg, *Systems Performance*** — perf-counter methodology.
- **FreeBSD `hwpmc`** — clean-room PMU abstraction.
- **Solaris/illumos `mdb`** — post-mortem debugger precedent.
- **Hubris `humility`** — Rust-embedded post-mortem tool; closest in
  spirit to what NARF wants. <https://github.com/oxidecomputer/humility>

## Distilled summaries

- `summaries/gdb-remote-protocol.md` — GDB Remote Serial Protocol, packet format, stop replies
- `summaries/elf-core-format.md` — ELF core dumps, program headers, NT_PRSTATUS/PRPSINFO
- `summaries/crash-utility.md` — Crash post-mortem debugger, macro framework, kernel analysis
- `summaries/humility-debugger.md` — Humility, domain-specific visibility, non-intrusive fault capture

## Open research questions

- PMU-counter multiplexing accuracy under NARF's domain-switch load
  (PKRS writes are frequent; does that perturb counter reads?).
- Minimum viable core-dump size vs. diagnostic value. Full domain
  state can be large.
- Attaching GDB across a PKS domain switch — do we stop all domains,
  or only the faulting one?
