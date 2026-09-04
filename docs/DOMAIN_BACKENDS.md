# Domain Backends — Hardware Enforcement Matrix

NARF's domain isolation is a runtime-selected backend. The framekernel
boots, probes CPUID / arch features, and picks the strongest enforcer
the silicon supports. The cap system, Narf-Ring contract, and same-VA
invariant are identical across backends — only the cost per crossing
and the per-domain count differ.

| Silicon | Backend | Switch cost | Domain count | Notes |
|---|---|---|---|---|
| Intel Sapphire Rapids and later (server), Alder Lake / Raptor Lake (client, where exposed) | **PKS** | One `WRMSR IA32_PKRS` (~tens of cycles, no TLB hit) | 16 | The reference fast path. CR4.PKS=1, per-PTE 4-bit PK field selects the domain. |
| aarch64 with **MTE** (Cortex-X2+, Apple M-series with MTE exposed, ARMv9 server cores) | **MTE** | One SR write (`SCTLR_EL1.TCF` + tag bits) | 16 | Tag-on-load enforcement at the 16-byte granule. Same hot-path cost class as PKS. |
| **AMD** Zen 3 / Zen 4 / Zen 5 (no PKS), pre-SPR Intel Xeon and Core (no PKS exposed) | **PCID** | One `MOV CR3` with PCID-preserve flag (~50–100 cycles, hot PCID stays warm) | 16 (capped — architecture has 4096 PCIDs) | Domain N → PCID N+1; 16 byte-cloned PML4s share downstream PDPTs (KAISER-style fan-out for kernel-shared mappings), each domain owns a private PDPT installed at PML4 slot 256+N. Accesses to a domain's private VA range from any other domain hard-fault at PML4 level. `memory::map_domain_private(D, va, pa, flags)` lands a leaf in domain D's subtree only. |
| aarch64 without MTE | **ASID-PT** *(planned)* | One `TTBR0_EL1` write with ASID | 16 | Conceptual mirror of PCID on x86_64. Not yet implemented; today's `frame/` boot path reports the fallback intent. |
| AMD SEV-SNP guest | *Could* use **VMPL** | `RMPADJUST` / `VMGEXIT` (~thousand cycles) | 4 (architectural cap) | Research only — see `memory/research/snp_vmpl.md`. Composes with SEV memory encryption. |
| Older silicon, no PK / MTE / PCID-class fallback acceptable | **SFI** *(research)* | Zero per crossing; cost in inserted bounds checks per memory op | Compiler-defined | Software fault isolation — Rust dialect verified at compile time. See `memory/research/sfi.md`. |

## What this means for security claims

On PKS or MTE silicon, the framekernel's domain story is
hardware-enforced at MSR / SR-write speed — the design's reference
deployment.

On AMD x86_64 today, the PCID backend is wired end-to-end:

- Boot enables `CR4.PCIDE` on the BSP and on every AP.
- The framekernel allocates 16 per-domain PML4s as byte-clones of the
  bootstrap (so kernel-shared mappings auto-fan-out via shared
  downstream PDPTs).
- A private PDPT is installed in each domain's PML4 at slot 256+N.
- The CR3-swap path is armed; cross-CPU TLB consistency is maintained
  by a `VECTOR_TLB_SHOOTDOWN` IPI broadcaster — `unmap_4kb` fans out
  to every online AP after the local INVLPG.
- Drivers claim private MMIO regions through
  `narf_drivers::claim_mmio_in_domain`, which lands the leaf inside
  the driver's own PML4 subtree only.

A cross-domain access to a private VA hits a not-present PML4E and
`#PF`s at the very first level of the walk — hardware-enforced, no
software check. Domain crossings cost ~50–100 cycles for the `MOV CR3`
(vs the ~tens-of-cycles `WRMSR` cost on PKS).

## What the two backends do and do not cover

They are not interchangeable, and this section exists because an earlier
version of it said "same correctness, different throughput class". The
throughput claim is right; the correctness one is not.

**Neither backend confines a domain from ordinary kernel memory.** PKS
`enter_domain(FRAME, D)` denies all sixteen keys and then re-allows two —
but `FRAME` is domain 0, and key 0 is what every untagged page carries,
so all untagged kernel memory stays readable and writable. PCID's clones
share every mapping outside the private slots for the same practical
effect. What both provide is *cross-domain* isolation: keeping domain A
out of domain B's resources.

**They cover different sets of resources, and that is the real
difference.**

  * **PKS protection is page-granular and follows the page.** Any leaf
    can carry `PtFlags::pk(D)`, wherever it is mapped, and `IA32_PKRS`
    denies it to every domain but the two allowed. `bpf_stack` does
    exactly this: its pages are tagged `pk(BPF)`, so no other domain may
    touch the BPF stack.
  * **PCID protection is PML4-slot-granular and covers only slot
    256+D.** The per-domain PML4s are byte-clones and `PML4[256..511]`
    is copied *by value*, so anything mapped outside the private slot is
    present and permitted in every domain's clone.

That gap is not hypothetical. BPF's own regions sit outside the private
range on purpose — `BPF_TEXT_PML4_SLOT` is 273, `BPF_ARENA_PML4_SLOT` is
275, and the BPF stack is `BPF_TEXT_BASE + 2 GiB`, so also slot 273. All
three are cross-domain protected under PKS, by their keys, and reachable
from every domain under PCID. `bpf_stack::map_stack_page` shows the seam
directly: it ORs in `pk(BPF)` only `if pks::is_active()`, because a PTE
key means nothing to the PCID backend, and there is no PCID equivalent
to reach for.

The exposure is asymmetric. `bpf_text::seal_mapping` rewrites the pack's
leaves to drop `WRITABLE` once a pack is published, independently of the
domain backend, so a foreign domain can *read* JIT'd text but not modify
it — W^X closes that vector, not the enforcer. The stack and the arena
stay read/write.

**This is now closed under PCID.** `domain::confine_shared_slots` runs
after the clones are built and zeroes each confined slot in the clones
that do not own it, driven by the `CONFINED_SLOTS` table:

| Slot | Contents | Owners |
|---|---|---|
| `BPF_TEXT_PML4_SLOT` (273) | JIT'd packs, `text_poke` windows, program stacks | `FRAME`, `BPF` |
| `BPF_ARENA_PML4_SLOT` (275) | arenas | `FRAME`, `BPF` |

`FRAME` keeps them because it is the TCB: the loader, JIT and verifier
write text before it is sealed, and removing the slots there would break
loading rather than harden it. `BPF` keeps them because
`bpf::domain::enter` switches CR3 to the BPF clone around every program
run, so that is the CR3 that must have the regions mapped.

The policy is a table and not an open-coded check because the same
"which domains may see this region" question is answered independently
by PKS (`PtFlags::pk`) and PCID (slot presence). Two mechanisms, one
intent; keeping the PCID half declarative puts the drift in one place.

**It deliberately does not touch task address spaces.** Those snapshot
the same range, and `reserve_kernel_slots` is sequenced before the first
`new_user_pml4` precisely so they capture the BPF entries — the boot-path
comment warns that a task CR3 holding a zero BPF entry triple-faults on
the first BPF access. Kernel-side BPF work (map updates from syscalls,
JIT writes, perf ring reads) runs on a task CR3 and is unaffected. Only
the sixteen domain clones are narrowed.

### The access graph this rests on

Confinement is safe only if nothing running inside a driver-domain guard
legitimately needs those regions. That graph is small enough to state in
full:

  * Driver domains are entered at exactly two sites, both in
    `modules/src/loader.rs`: around a module's `init()` and its `exit()`.
  * The kernel ABI a module may call is the `kernel_abi!` table in
    `modules/src/kabi.rs` — `narf_printk`, `narf_kmalloc`, `narf_kfree`,
    `narf_monotonic_ns`. None reach slots 273 or 275, and `register_all`
    is the only path that populates KSYMTAB.
  * A module's own image is at `MODULE_VA_BASE` (slot 511), so narrowing
    273/275 does not unmap the code that is running.
  * BPF firing from a tracepoint while a guard is held nests a crossing
    into the BPF clone, where the regions are mapped.

One coupling is worth knowing about: **slot 273 is not BPF-only.**
`text_poke`'s per-CPU scratch windows sit at `BPF_TEXT_BASE +
BPF_TEXT_USABLE`, so the slot holds the pack region at +0, the poke
windows at +1 GiB and the program stacks at +2 GiB. Confining 273
therefore also removes the poke window from driver clones. That is safe
because text patching happens at load/seal time on a task CR3 and never
inside a guard, but it is an accident of layout rather than a decision,
and it is a trap for whoever first patches text from module init. Moving
the poke window to slot 274 — which is unclaimed — would let the table
above say what it means.

### What is verified and what is not

The policy is covered by `smoke_pcid_confined_slot_policy`, which is
ungated and runs everywhere. The structural assertion that it landed in
the clones, `smoke_pcid_confined_slots_applied`, gates on
`pcid::is_active()` and therefore **skips on every runner available
today**: QEMU's TCG does not implement PCID even under `-cpu max,+pcid`,
and the development host's KVM reports `CPUID(1).ECX[17] = 0`. The PCID
enforcement path has never executed on hardware we have. Treat the
confinement as reviewed and unexercised until a PCID-capable runner
exists.

The aarch64 ASID-PT fallback for non-MTE silicon is conceptually
identical to PCID and is the planned analog. Today, aarch64 boot
without MTE reports the fallback intent but does not yet install
private subtrees.

## How the kernel picks at boot

`frame/src/x86_64/cpu.rs` and `frame/src/aarch64/cpu.rs` probe
features at BSP startup:

1. If `CPUID(7,0).ECX[31]` indicates PKS (Intel) or
   `ID_AA64MMFR2_EL1.TCF` indicates MTE (aarch64), the strong backend
   is chosen.
2. Otherwise, if PCID is available (Intel + AMD on x86_64), the
   PCID-tagged backend is wired.
3. Otherwise, the ASID-PT fallback intent is logged and the boot
   continues in single-domain mode.

The choice is logged in `boot-init`'s subsystem table. `domain::backend()`
returns the active backend at runtime.

## Why three backends instead of one

Sapphire Rapids' PKS is the fastest path but isn't shipping in
consumer laptops. MTE is shipping in some ARM laptops (Apple M3+ with
MTE exposed by macOS / asahi-style Linux) but not in any commodity
server SKU. PCID-tagged page tables cover the realistic deployment
surface for everything else — AMD desktops, AMD laptops, older Intel
clients, the entire pre-Sapphire-Rapids Xeon line.

A single-backend design would either force a hard hardware floor
(PKS-only) or accept a slow boundary (PCID-only) on silicon that has
a fast one. The runtime selection lets the same kernel binary deploy
across all three surfaces with the right cost.
