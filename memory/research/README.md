# memory — Research

## Primary sources

- **Intel SDM Vol. 3A — Chapter 4 (Paging) and §4.6.2 (Protection Keys
  for Supervisor-Mode Pages, PKS)**. <https://www.intel.com/sdm>
- **Intel "Protection Keys for Supervisor Pages" whitepaper**.
  <https://www.intel.com/content/www/us/en/developer/articles/technical/protection-keys-for-supervisor-pages-pks.html>
- **Arm ARM — D5 (Memory Management) and D6 (Memory Tagging Extension)**.
  <https://developer.arm.com/documentation/ddi0487/latest/>
- **"Memory Tagging Extension: Enhancing Memory Safety through
  Architecture" (Arm, 2019)** — whitepaper.
  <https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Arm_Memory_Tagging_Extension_Whitepaper.pdf>

## Secondary sources

- **OSDev wiki — Paging, Higher Half Kernel**. <https://wiki.osdev.org/Paging>
- **Linux `mm/` — buddy allocator and `SLUB`**. <https://github.com/torvalds/linux/tree/master/mm>
- **"Linux kernel PKS support" LWN coverage**. <https://lwn.net/Articles/826092/>
- **Redox `kernel/src/memory` and `buddy_alloc` crate**.
- **`linked_list_allocator` + `talc` + `buddy_system_allocator` Rust crates** — comparison.

### Page-allocation models & multi-page units

- **Linux folio API** — "The end of the page? Not quite" (LWN) and the
  upstreaming series. Consolidates head-page + compound-page into one
  typed `struct folio`; foundation for the modern page cache.
  <https://lwn.net/Articles/849538/> / <https://lwn.net/Articles/893512/>
- **Linux huge-page docs (THP, hugetlbfs)** — `Documentation/admin-guide/mm/`.
  <https://docs.kernel.org/admin-guide/mm/transhuge.html>
- **Arm ARM §D8 — Translation granule sizes + contiguous hint**.

### Slab / object allocators

- **Bonwick, "The Slab Allocator: An Object-Caching Kernel Memory
  Allocator" (USENIX 1994)** — canonical SLAB paper; concept of object
  caches, constructor/destructor, and slab colouring.
  <https://www.usenix.org/publications/library/proceedings/bos94/bonwick.html>
- **Bonwick & Adams, "Magazines and Vmem" (USENIX 2001)** — per-CPU
  magazines layered on top of SLAB; direct ancestor of jemalloc's
  `tcache` and tcmalloc's thread caches.
  <https://www.usenix.org/legacy/event/usenix01/full_papers/bonwick/bonwick.pdf>
- **Linux SLUB** — simpler successor to SLAB; current kernel default.
  Source under `mm/slub.c`.
- **jemalloc** — size-class geometry, arena-per-thread, purge/decommit.
  <https://jemalloc.net/> / Evans, "A Scalable Concurrent malloc(3) Implementation for FreeBSD" (BSDCan 2006).
- **tcmalloc** — Google's TLS-cached allocator; thread caches, spans,
  central free lists. <https://google.github.io/tcmalloc/design.html>
- **mimalloc** — Microsoft's page-based allocator with free-list sharding.
  Useful precedent for low-fragmentation design on mixed workloads.
  <https://github.com/microsoft/mimalloc>

## Distilled summaries

- [`summaries/intel-pks.md`](./summaries/intel-pks.md) — PKS semantics,
  PKRS MSR, protection check order.
- [`summaries/arm-mte.md`](./summaries/arm-mte.md) — MTE model, tag
  granule, sync vs async fault modes.

## Domain-isolation backend candidates

- [`snp_vmpl.md`](./snp_vmpl.md) — AMD SEV-SNP VMPL as a candidate
  backend on confidential-VM deployments. Parked: 4-level cap, guest-only,
  ~kilocycle switch. PCID is the AMD path of record.
- [`sfi.md`](./sfi.md) — Software Fault Isolation as a silicon-agnostic
  backend. Parked: trust shifts to compiler + verifier; Rust dialect
  not yet ready.

## Fetched this round

### 2026-04-22

- `summaries/intel-sdm-paging-pks.md` — Intel paging hierarchy, PKS keys, per-domain access control
- `summaries/arm-mte-whitepaper.md` — MTE tag granules, synchronous/asynchronous modes, tag generation
- `summaries/linux-pks-lwn.md` — Linux PKS integration, per-CPU PKRS, domain-specific ranges

## Open research questions

- Latency of `WRMSR(IA32_PKRS)` on domain switch — benchmark target.
- MTE async mode vs sync mode: does async preclude clean fault attribution?
- NUMA-aware allocation: worth it pre-Stage 4?
- **Folio or frame-array?** Adopt Linux's folio concept as NARF's
  multi-page allocation unit, or keep `PhysFrame` as the sole currency
  and represent "order-k" as `[PhysFrame; 2^k]`? Folios are clearly the
  right answer for a future page cache; the question is whether we
  commit to that shape in Stage 1 or retrofit in Stage 3.
- **Slab implementation choice.** SLUB-style (simple, central free
  lists) vs. magazines-over-SLAB (Bonwick 2001) vs. jemalloc-style
  arena-per-domain. Measure read/free latency on NARF's domain-switch
  overhead before committing — per-domain arenas compose naturally
  with our PKS isolation but add RSS.
- **Huge-page adoption pressure.** `filesystem/` page cache and
  per-driver DMA buffers will want 2 MiB / 1 GiB folios. When does
  demotion (split a huge folio back into base pages under memory
  pressure) become mandatory? Linux's THP khugepaged path is a
  cautionary tale.
- **Contiguous-hint bookkeeping on aarch64.** Setting the `CONT` bit
  requires all 16 PTEs to stay in sync; partial unmap forces a
  `break-before-make` sequence. Is this worth the TLB savings, or do
  we stick with non-contiguous mappings for simplicity?
