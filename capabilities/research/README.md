# capabilities — Research

## Primary sources

- **seL4 Reference Manual** — §2 (Capabilities), §3 (System Calls), §4
  (Invocations). <https://sel4.systems/Info/Docs/seL4-manual-latest.pdf>
- **KeyKOS Architecture** (Hardy, 1985) and **EROS: A Fast Capability
  System** (Shapiro, Smith, Farber, SOSP 1999).
  <https://www.cis.upenn.edu/~KeyKOS/>
- **"Capability Myths Demolished"** (Miller, Yee, Shapiro, 2003).
  <http://srl.cs.jhu.edu/pubs/SRL2003-02.pdf>

## Secondary sources

- **Fuchsia handles / Zircon object model** — modern OO-capability kernel.
  <https://fuchsia.dev/fuchsia-src/concepts/kernel/concepts>
- **CHERI capability hardware** — ISA-level caps; interesting for long-term
  evolution. <https://www.cl.cam.ac.uk/research/security/ctsrd/cheri/>
- **Redox — capability model in `syscall/scheme`** (not quite a cap OS but
  has relevant ideas).
- **Hubris tasks + IPC** — compile-time-typed message passing with
  capability-flavour.

## Distilled summaries

- [`summaries/sel4-capabilities.md`](./summaries/sel4-capabilities.md) —
  cap types, CSpace, CDT, invocation, revocation.

## Fetched this round

- summaries/keykos-eros-architecture.md — Unforgeable tokens, CSpace isolation, epoch-based revocation, and potency levels
- summaries/capability-myths.md — Object capabilities vs. ACLs, Principle of Least Authority, and resource-side revocation

## Open research questions

- Is CDT's memory overhead acceptable on a system with many tasks × many caps?
- How do we keep derivation type-checked in Rust when rights are a bitset?
  (Phantom-type tricks vs. const generics vs. newtype-per-rights.)
- Endpoint caps (seL4) vs. Narf-Ring handles — are they the same thing in NARF?
