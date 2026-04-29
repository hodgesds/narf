# Research note — AMD SEV-SNP VMPL as a domain-isolation backend

## What it is

AMD Secure Encrypted Virtualization with Secure Nested Paging (SEV-SNP)
exposes **Virtual Machine Privilege Levels** (VMPL0–VMPL3) — four
hardware-enforced privilege rings *inside* a single SNP guest. Each
4 KiB guest page can be tagged in the Reverse Map Table (RMP) with the
minimum VMPL allowed to access it. A guest-side `RMPADJUST` instruction
mutates the per-page VMPL tag; switching execution between VMPLs goes
through `VMGEXIT` to the hypervisor.

Primary references:
- AMD64 APM Vol. 2, §15.36 — SEV-SNP.
- AMD "SEV-SNP: Strengthening VM Isolation with Integrity Protection
  and More" whitepaper (2020).
- "Severed: Asymmetric Privilege Inside SEV-SNP Guests" — usage
  patterns for VMPL-based intra-guest isolation (academic, 2023).

## Why it is a candidate for NARF

- **Hardware-enforced** without depending on Intel-only PKS. AMD-native.
- **Same VA across levels** within a guest. Compatible with Narf-Ring's
  zero-copy invariant.
- **Composes with memory encryption.** A confidential-VM deployment of
  the framekernel could place the TCB at VMPL0 and drivers at VMPL1+,
  inheriting page-level integrity protection from SNP.

## Why we are not building it now

1. **Domain count cap.** VMPL has 4 levels (VMPL0–VMPL3). NARF's
   domain API is shaped around 16 domains. Collapsing 16 driver
   categories into 4 VMPLs forces architectural compromises ("all
   block drivers share VMPL1") that weaken the isolation story.
2. **Bare-metal exclusion.** VMPL only exists inside an SEV-SNP guest.
   Bare-metal AMD silicon gets no benefit. The PCID fallback covers
   both deployments uniformly; VMPL would be a guest-only branch.
3. **Switch cost.** `VMGEXIT` to the hypervisor for a level switch is
   ~thousand-cycle class — slower than the PCID fallback, let alone
   PKS. Worse hot-path cost than the alternative we already have.
4. **Trust model widens.** VMPL enforcement assumes the AMD-SP / PSP
   firmware behaves correctly. The NARF threat model treats
   hypervisor + firmware as adversarial; VMPL would push part of the
   isolation guarantee onto code outside the TCB.

## What would change to revisit

- A confidential-computing deployment story becomes a stated NARF goal
  (it currently is not).
- The 4-level cap is acceptable because the deployment groups drivers
  by trust level rather than by category (e.g. attested device drivers
  at VMPL1, untrusted device drivers at VMPL2).
- AMD ships a hardware-assisted VMPL switch path with cost in the
  WRMSR class (currently no such path exists publicly).

Until those conditions hold, **no implementation work**. The PCID
backend is the AMD path of record.
