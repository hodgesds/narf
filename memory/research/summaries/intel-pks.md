# Intel PKS — Protection Keys for Supervisor Pages

**Primary source:** Intel® 64 and IA-32 Architectures Software Developer's
Manual (SDM), Vol. 3A §4.6.2. Intel whitepaper "Protection Keys for
Supervisor-Mode Pages." LWN coverage "Protection keys for the kernel."

> Distilled for NARF design. Treat this as a reading-notes file, not a spec.

## What it is

PKS adds a software-controlled domain tag to every supervisor-mode page.
The MMU still enforces U/S, R/W, XD, etc.; PKS is an *additional* check
that happens after those. Crucially, the rights for each PKS key can be
updated by a single MSR write with no TLB shootdown, so domain switches
are cheap.

PKS is the supervisor analogue of PKU (protection keys for user pages,
Skylake-X+). PKU affects user accesses; PKS affects supervisor accesses.
Both coexist and are orthogonal.

## Keys

- **16 keys** (4 bits), numbered 0..15, per page.
- The key lives in PTE bits **59..62** (the "protection key" field).
- Key 0 is the default for any page where the field is zero — useful
  for legacy / untagged pages.

## IA32_PKRS MSR

Per-CPU, 32 bits, two bits per key:

```
bit 2k     — Access Disable for key k  (AD)
bit 2k + 1 — Write  Disable for key k  (WD)
```

So bits 0..1 = key 0, bits 2..3 = key 1, ... bits 30..31 = key 15.

Writing `IA32_PKRS` (MSR `0x6E1`) updates the rights in one instruction.
A domain switch is a `WRMSR IA32_PKRS, <mask>` — no TLB invalidation,
no page-table edit. On current silicon this is the cheapest way to flip
a set of permissions that the TLB already knows about.

## Enable bits

- `CR4.PKS` (bit 24) enables the PKS feature itself.
- CPUID leaf 7 sub-leaf 0, ECX[31] ("PKS") advertises availability.

## Access check order

For a supervisor access to a page with key k, the CPU checks, in order:

1. Paging permissions (present, R/W, user/supervisor, XD).
2. CR0.WP and SMAP/SMEP as applicable.
3. PKS: if `IA32_PKRS.AD[k] == 1`, deny all access. Else if the access
   is a write and `IA32_PKRS.WD[k] == 1`, deny.

A PKS denial raises a page fault with `PFEC.PK` set so the kernel can
tell a PKS violation apart from a classic fault.

## Interaction notes

- **Instruction fetches** are *not* gated by PKS (documented). PKS only
  gates data reads and writes. Defence against code injection into a
  foreign domain relies on XD + SMEP + CET, not PKS.
- **SMAP** must still be enabled. PKS does not replace it.
- PKS protection does not apply to page-walker accesses or to the GDT/IDT
  descriptors — architectural fetches bypass.
- Updates to `IA32_PKRS` do not serialise prior loads; if an OS writes
  `PKRS` and then tries to immediately access a newly-allowed page, it
  should treat the MSR write as a dependency barrier for correctness
  reasoning (check SDM for precise serialisation rules before Stage 2
  lands).

## Why it matters for NARF

- **16 domains ↔ 16 PKS keys** maps one-to-one. Our `DomainId` is a PKS
  key directly.
- Domain switch = one `WRMSR`. This is the central performance claim of
  the framekernel: domain ≠ address space, so no TLB flush.
- Because instruction fetches aren't gated, entry points into each domain
  must be constrained by code placement + control-flow integrity (CET)
  so a bug in one driver can't jump to code in another domain's pages.
- Page fault handler must branch on `PFEC.PK` and attribute to the
  owning domain (i.e. the key in the faulting PTE), so domain-violation
  telemetry is clean.

## Open questions this raises for the NARF spec

- Baseline CPU requirement: Sapphire Rapids (SPR)+ for PKS. Document in
  `arch/specification/spec.md` that PKS absence fails boot in Stage 2.
- Errata search required for first-gen PKS silicon.
- Measure `WRMSR(IA32_PKRS)` latency on target hardware — numbers go
  into `scheduler/research/` for direct-context-transfer budgeting.
