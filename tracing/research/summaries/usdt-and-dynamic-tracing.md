# USDTs and Dynamic Tracing

**Primary sources:** Cantrill et al., "Dynamic Instrumentation of
Production Systems" (USENIX ATC 2004); `sys/sdt.h` header (SystemTap);
Linux kernel `Documentation/trace/{kprobes,tracepoints,uprobetracer}.rst`;
Linux `tools/perf/Documentation/perf-probe.txt`.

> Distilled for NARF. Reading notes.

## USDT — Userland Statically Defined Tracing

Originated in DTrace; ported to SystemTap's `sys/sdt.h`, then widely
adopted (glibc, PostgreSQL, Node.js, MySQL, Python). The idea:

- At source level, the author annotates interesting points:
  ```c
  DTRACE_PROBE3(provider, probename, arg1, arg2, arg3);
  ```
- At compile time this expands to **a single `nop` instruction** plus
  an ELF note in `.note.stapsdt` describing:
  - provider name
  - probe name
  - address of the `nop`
  - semaphore address (optional, lets the program skip arg prep when unarmed)
  - argument specification string (register / memory location of each arg)
- At runtime, a tracer walks the notes, decides what to arm, and
  patches the `nop` into a trap / branch. When the probe fires, the
  tracer reads the args from the documented locations.

Properties worth internalising:

1. **Zero hot-path cost when unarmed.** One `nop`, no branch predict.
2. **Self-describing.** All metadata is out-of-band; the tracer does
   not need debug symbols.
3. **Decoupled lifecycle.** Tracer can arm/disarm any time without
   recompiling the target.
4. **Cheap to place liberally.** Because unarmed cost is ~1 cycle,
   source authors can pepper USDTs across hot paths.

## Dynamic probes (KProbes / UProbes / ftrace function hooks)

Complementary to USDT:

- **KProbes** — Linux kernel. Overwrite an arbitrary instruction with
  `int3` (x86) / `BRK` (aarch64); on trap, relocate and execute the
  original instruction out-of-line, run probe handler, continue.
  Optimised variants: **optimized kprobes** use a jump thunk when a
  5-byte `jmp` displacement fits the site.
- **UProbes** — the same idea for user-space: patches a process's
  executable pages.
- **ftrace function_graph** — exploits the `-pg` mcount preamble every
  function has, lets the tracer hook entry + return cheaply; hence
  function-call-graph timing without per-site setup.

Compared with USDT:

| Aspect               | USDT                     | KProbe / UProbe        |
| -------------------- | ------------------------ | ---------------------- |
| Probe locations      | author-picked, marked    | any instruction        |
| Metadata             | compile-time ELF notes   | synthesised at install |
| Arg access           | documented registers     | needs DWARF/debug info |
| Cost when unused     | 1 nop                    | 0 (nothing installed)  |
| Arming cost          | one patched instruction  | one patched instruction + trampoline setup |
| Target modification  | none (patch at runtime)  | none                   |

## How NARF uses both

- `observability/` §3.2 makes USDT-style markers the **blessed hot-path
  instrumentation**. Source authors add `usdt!(provider, name, args)`
  to places worth publicly labelling.
- `observability/` §3.3 keeps dynamic probes (`install_probe`) for
  ad-hoc investigation of code the author didn't pre-mark.
- Both share the same arming path, same `ProbeAction` surface, same
  capability gate. The only difference is *where the metadata came
  from*.
- `observability/` §3.3.1 (`FnTime`) works transparently against
  either: pair a USDT enter + exit for the blessed hot path, or
  install an entry/return dynamic probe pair for an arbitrary function.

## Arming discipline — cross-modifying code

Patching a live executable page requires care:

- **x86_64:** use the SMC (self-modifying code) protocol — `stop_machine`
  or the Intel-recommended atomic 5-byte `jmp` replacement. Ensure no
  CPU is mid-fetching the bytes being replaced. Linux's
  `text_poke_bp` uses an `int3` breakpoint as a synchronising atomic
  transition.
- **aarch64:** flush I-cache for the patched range, execute `DSB ISH`
  + `ISB`, possibly IPI other CPUs to sync.

NARF's arming path will wrap these into an arch HAL op
`patch_instruction(va, new_bytes)` and own the serialisation. Batch
arming (arm N probes in one stop-the-world pass) to amortise cost.

## Security notes

- USDT notes are *informational*. Presence of a probe site does not
  itself grant observability; a tracer still needs `Cap<Probe, Install>`
  and, for interesting data, further caps (`Cap<Pmu, Read>`,
  `Cap<TraceRing<D>, Recv>`).
- Patching instructions in a domain requires `Cap<Domain(D), Patch>`.
  Reject attempts to patch TCB pages from a non-TCB cap holder.
- Disarming must be atomic from the target's perspective: a probe
  firing mid-disarm must either run to completion or not fire.

## Takeaways for the NARF spec body

- Adopt USDT's ELF-note layout near-verbatim, namespaced as
  `.note.narf.probes`. Compatibility with bpftrace-class tooling is a
  free bonus.
- Keep the `ProbeAction` enum declarative; do not bolt on a VM.
- Design `FnTime` so USDT-pair timing and function entry/return timing
  share a single per-CPU shadow stack.
