# ARM MTE — Memory Tagging Extension

**Primary source:** Arm ARM (DDI 0487) §D6 "Memory Tagging Extension";
Arm whitepaper "Memory Tagging Extension: Enhancing Memory Safety
through Architecture" (2019).

> Distilled for NARF design. Reading notes, not a spec.

## What it is

MTE attaches a **4-bit tag** to every 16-byte aligned region of memory
("tag granule") and a matching 4-bit tag in the *top byte* of a virtual
address ("address tag"). On a load/store, hardware checks that the
pointer tag matches the memory tag for the granule being accessed.

A mismatch can be delivered in one of three modes: **synchronous**
(precise fault, hi-latency), **asynchronous** (imprecise but cheap —
the CPU flags the mismatch in a register and keeps running), or
**asymmetric** (sync on loads, async on stores). NARF's domain use case
wants *synchronous* so faults are attributable; we pay the latency.

## 4-bit tags → 16 values

Same ceiling as PKS's 16 keys, which is why the framekernel's 16-domain
model maps cleanly across both archs.

## Tag storage

- Tag bits are stored out-of-band by the CPU. On Arm implementations
  that's typically carved out of main memory at a small (~3%) overhead.
- Tag access goes through dedicated cache operations; `LDG` / `STG` load/
  store a tag, and variants `LDGM` / `STGM` do bulk.
- `DC ZVA` extensions zero tags; `IRG` generates a random (or provided)
  tag for a pointer.

## Enabling MTE

- Feature detection: `ID_AA64PFR1_EL1.MTE` non-zero.
- Enable: set `SCTLR_ELx.TCF` (tag check fault) and `TCF0` for EL0; set
  `TCR_ELx` bits for tag-checked address ranges and the TBI (top-byte
  ignore) already assumed for non-MTE code.
- EL1 (kernel) side uses `TCR_EL1.TCMA1`, `TBI1`.

## Address tagging vs. access tagging

Top-byte-ignore (TBI) has existed on aarch64 since ARMv8.0. MTE
*uses* the top byte (specifically bits 59:56) as the tag. So pointer
tagging already composes with existing kernel code that honours TBI.

## Why it matters for NARF

- MTE is the aarch64 equivalent of PKS for our domain model. A domain
  is a tag value; tagged pages belong to that domain; the CPU checks on
  every access.
- Domain switch on aarch64 is not as cheap as on x86_64. PKS is a
  single MSR write that changes rights; MTE checking is per-access and
  the "domain" is baked into each tagged pointer. The idiomatic
  equivalent of a switch is *using the right tags* in pointers, plus
  `TCMA1` / `TCF` to enable checking at the right level.
- The Frame must decide between sync and async TCF based on driver
  trust: Stage 2 will use **sync** universally so a misbehaving driver
  faults precisely inside its domain entry.
- Tag coverage is per-granule (16 B). That's finer than a page, which is
  great for safety but forces the allocator to align domain ownership
  to 16 B.

## Differences from PKS we need to handle in the HAL

| Concept            | x86_64 PKS             | aarch64 MTE            |
| ------------------ | ---------------------- | ---------------------- |
| Granule            | page (4 KiB)           | 16 B                   |
| Tag width          | 4 b (16 keys)          | 4 b (16 tags)          |
| Rights change      | `WRMSR IA32_PKRS`      | change pointer tag in use; TCF config |
| Fault signal       | `#PF` with PFEC.PK     | synchronous abort w/ ESR `DFSC = 0x11/0x10`, or async via TFSR_EL1 |
| Instruction fetch  | not covered            | not covered (as of MTE1) |
| TLB interaction    | none (MSR)             | TLB caches tag config; some changes require TLBI |

## Open questions this raises for the NARF spec

- NARF depends on *domain ownership at the page level* on x86_64; on
  aarch64 it could be finer than a page. Do we standardise on
  "page-level domains" everywhere for spec simplicity, or expose
  sub-page domains on aarch64?
- Tag randomisation (IRG) is an attacker-mitigation feature for memory
  safety. Do we use it inside NARF, or fix tags per domain?
- TCMA (tag-check mask) per address space — useful for allowing uncheck
  regions like device MMIO.
