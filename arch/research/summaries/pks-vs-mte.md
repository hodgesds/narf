# PKS (x86_64) vs. MTE (aarch64) — cross-arch comparison

**Primary sources:** Intel SDM Vol. 3A §4.6.2 (PKS), Arm ARM §D6 (MTE).
See also [`../../memory/research/summaries/intel-pks.md`](../../memory/research/summaries/intel-pks.md)
and [`../../memory/research/summaries/arm-mte.md`](../../memory/research/summaries/arm-mte.md)
for the individual deep reads.

> Distilled for NARF design. Side-by-side to keep the HAL honest.

## The point of this doc

NARF's framekernel uses one hardware feature per arch to implement its
16-domain model. The two features are not 1:1 in mechanics, but they are
1:1 in bits (4-bit key / 4-bit tag → 16 values). This doc pins down
where the abstraction in `arch/` must paper over real differences and
where NARF must not pretend the two are the same.

## Side-by-side

| Concept                | Intel PKS (x86_64)                         | Arm MTE (aarch64)                                |
| ---------------------- | ------------------------------------------ | ------------------------------------------------ |
| Number of partitions   | 16 keys                                    | 16 tags                                          |
| Where the tag lives    | PTE bits 59..62                            | Top byte of VA (bits 59..56) + tag per 16 B granule |
| Granularity            | page (4 KiB)                               | 16 B                                             |
| Access check           | CPU compares PKRS (MSR) rights for key     | CPU compares pointer tag to memory tag           |
| Change rights          | one `WRMSR IA32_PKRS` (cheap)              | update pointer(s) or TCF mode                     |
| Applies to fetches     | No (data only)                             | No (data only; MTE1)                              |
| TLB invalidation       | Not required on rights change              | Some changes require `TLBI`                        |
| Fault signal           | `#PF` with `PFEC.PK`                        | sync abort (ESR DFSC `0x10/0x11`) or async via `TFSR_EL1` |
| Enable                 | `CR4.PKS`                                   | `SCTLR_ELx.{TCF,ATA}`, `TCR_ELx.{TBI1,TCMA1}`      |
| CPUID / feature ID     | CPUID.7.0:ECX[31]                           | `ID_AA64PFR1_EL1.MTE`                              |

## Implications for the NARF HAL

1. **"Domain switch" is not one operation.** On x86_64 it's a single
   MSR write with no TLB effects. On aarch64 it's a combination of
   "use this pointer" (whose top byte is the tag) plus TCF enable, and
   any change to TCMA / `TCR_EL1.TBI1` is a real reconfiguration.
   The HAL trait method `set_domain_rights(id, rights)` must be
   honest about this asymmetry.
2. **Granularity.** PKS is page-scoped, MTE is 16 B. NARF commits to
   page-scoped domain ownership in its data model (matches the coarser
   arch). The MTE backend just keeps all granules of a page tagged the
   same; it never exposes finer granularity to higher subsystems.
3. **Fault attribution.** On x86_64, `PFEC.PK` cleanly says "this was
   a PKS violation." On aarch64, sync mode is similarly clean; async
   mode is not. NARF selects **sync** mode on aarch64 for domain
   enforcement (pay latency, gain attribution); async is reserved for
   opt-in memory-safety features inside a domain.
4. **Instruction fetches are not gated on either arch.** Both arches
   require XD/PXN for code-execution control. The framekernel leans
   on CET (x86_64) and BTI+PAC (aarch64) to make cross-domain jumps
   unforgeable. This is a security-model concern, not a memory one.
5. **Rights model.** PKRS encodes per-key AD (access disable) + WD
   (write disable) — 2 bits per key → read-only / read-write / no-access.
   MTE is a match/nomatch check: "may access" vs. "tag check fault,"
   with no built-in write-vs-read distinction. To get "read-only"
   semantics on aarch64, NARF uses page-table AP bits as on a
   non-MTE system; MTE only gives us "this page belongs to tag T."
   In other words, **domain == tag == key**, but **per-domain R/W
   policy** lives in the HAL on top of MTE for aarch64.

## What `arch/` ends up exposing

A trait surface roughly:

```rust
pub trait DomainPrimitive {
    fn supported_domain_count() -> u8;           // 16 on both
    unsafe fn assign_domain(va: VirtRange, id: DomainId);
    unsafe fn set_rights(id: DomainId, rights: DomainRights);
    unsafe fn enter_domain(id: DomainId);        // cheap: MSR or pointer discipline
    fn last_fault() -> Option<DomainFault>;      // attribution
}
```

On x86_64, `assign_domain` edits PTE PK bits, `set_rights` is one
`WRMSR IA32_PKRS`, and `enter_domain` is a no-op plus possibly a
barrier (since entering a domain means *using* the rights that
`set_rights` already established).

On aarch64, `assign_domain` writes tags for every granule in the
range, `set_rights` collapses to a no-op (rights enforced via
page-table AP), and `enter_domain` is the moment we start using
pointers with the domain's tag.

## Open questions this raises

- Do we ever need >16 domains? Both arches cap us here.
- Virtualisation (guest OS inside NARF) complicates both: nested PKS
  and MTE have specific behaviour that future stages must consider.
- Future hardware: LAM + LASS (x86_64), MTE2 and MPAM (aarch64). Keep
  watching; do not bake assumptions that foreclose them.
