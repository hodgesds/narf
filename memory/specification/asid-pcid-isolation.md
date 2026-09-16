# asid-pcid-isolation — Tagged page-table isolation

> Status: **v0.2** (Stage 5 land). Supplements
> `memory/specification/spec.md` §5 with the runtime surface for
> per-domain page-table roots tagged with PCID (x86_64) / ASID
> (aarch64), the rollover allocator, and the cross-CPU TLB
> shootdown protocol.

This spec covers four primitives:

  * **Per-domain page-table root** — each NARF driver domain owns
    a private user-half PML4 (x86_64) or TTBR0 root (aarch64) so
    address-space changes don't leak across domains.
  * **ASID / PCID allocator** — stable domain mappings plus lifetime-scoped
    process PCIDs/ASIDs. Process tags are invalidated before reuse; exhaustion
    or an incomplete x86 CPU feature set safely falls back to tag-0 flushing.
  * **Selective TLB invalidation** — `INVPCID` on x86_64 + `TLBI
    ASIDE1IS` on aarch64 to invalidate the entries for one tag
    without flushing the whole TLB.
  * **Cross-CPU TLB shootdown** — IPI-based fan-out to peer CPUs
    when an invalidation must be observable system-wide. Becomes
    real once SMP bring-up is wired (`arch/x86_64/smp.rs`); on
    a single-CPU boot it's a no-op.

It locks the API shape so `memory/`, `frame/`, and `scheduler/`
can be coded against a stable surface.

## 1. Per-domain page-table root

### 1.1 Layout

x86_64:

| half        | source              | per-domain? |
|-------------|---------------------|-------------|
| Lower (0..0x0000_8000_0000_0000) | PML4[0..255]  | yes — private subtree per domain |
| Upper (0xFFFF_8000_0000_0000..)  | PML4[256..511] | no — shared kernel half (cloned by `clone_kernel_half`) |

aarch64:

| half  | register   | per-domain? |
|-------|------------|-------------|
| Lower | TTBR0_EL1  | yes — full root per domain |
| Upper | TTBR1_EL1  | no — single shared kernel root |

### 1.2 Construction

```rust
pub struct PerDomainRoot {
    pub domain:     DomainId,
    /// Phys of the user-half root (PML4 on x86_64, TTBR0 on aarch64).
    pub root_phys:  u64,
    /// Generation counter — bumps when the ASID/PCID is reassigned
    /// after a rollover.
    pub generation: u64,
}

pub fn allocate_root(domain: DomainId) -> Result<PerDomainRoot, AllocError>;
pub fn free_root(root: PerDomainRoot);
```

`allocate_root` allocates a fresh 4 KiB root frame, copies the
upper-half kernel mappings (a `clone_kernel_half(into)` helper
on the existing paging crate), and registers the root in a
per-domain table.

### 1.3 Switching

```rust
pub unsafe fn switch_to(root: &PerDomainRoot);
```

x86_64: writes `CR3 = (root.root_phys & PML4_MASK) | (pcid_for(root) as u64) | NOFLUSH`.
aarch64: writes `TTBR0_EL1 = (root.root_phys & BADDR_MASK) | ((asid_for(root) as u64) << 48)`,
then `DSB ISH; ISB`.

`pcid_for(root)` / `asid_for(root)` consult the allocator
(§2). Both paths are non-flushing — TLB entries from the
destination tag stay live.

## 2. ASID / PCID allocator

### 2.1 Tag space

| arch    | width | reserved   | usable                          |
|---------|-------|------------|---------------------------------|
| x86_64  | 12 bits | 0 (flushing fallback), 1..16 (domain roots) | 17..4095 for process roots |
| aarch64 | 8 / 16 bits (per `ID_AA64MMFR0_EL1.ASIDBits`) | 0 (flushing fallback), 1..16 (domain roots) | 17..(2^N - 1) for process roots |

### 2.2 Allocation policy

Both architectures assign the 16 domain roots stable tags 1..=16, matching the
x86 domain-enforcer encoding and keeping domain tags disjoint from processes.

Each `AddressSpace::new_for_user` reserves one lifetime tag from 17 through the
architectural maximum (4095 on x86_64; the maximum encoded by
`ID_AA64MMFR0_EL1.ASIDBits` on aarch64). On x86_64, boot enables CR4.PCIDE on
the BSP and every AP independently of the domain backend, then enables process
PCIDs only if every online CPU also advertises INVPCID. This all-CPU gate makes
a nonzero process PCID uniformly installable and retireable; otherwise every
new address space receives tag 0 and uses the prior flushing path. A CPU that
rejoins after the gate closes invalidates every local PCID context before it
publishes itself online; a CPU lacking either feature fails before publication.

The tag remains bound to its root for the complete `AddressSpace` lifetime.
Last-owner teardown issues a synchronous tag-wide invalidation before clearing
the allocator bit (`INVPCID` plus targeted IPI rendezvous on x86_64, `TLBI
ASIDE1IS` on aarch64), so no concurrent allocation can reissue a tag while
stale translations remain. Pool exhaustion returns tag 0. A tag-0 root switch
does not use NOFLUSH and therefore retires the previous tag-0 context.

`allocator_init` is one-shot in production and allocation lazily invokes it, so
a later explicit call cannot reset live tag ownership. The kernel-test reset
hook clears only the domain-generation cache; it deliberately preserves process
ownership so test ordering cannot reissue a still-live process tag.

### 2.3 API

```rust
pub fn allocator_init();
pub fn pcid_for(domain: DomainId) -> u16;     // x86_64 (1..=16)
pub fn asid_for(domain: DomainId) -> u16;     // aarch64 (1..N)
pub fn current_generation() -> u64;
pub fn invalidate_tag(domain: DomainId);      // arch-dispatched
pub fn rollover_now();                         // generation += 1, full flush
```

## 3. Selective TLB invalidation

### 3.1 x86_64 (`INVPCID`)

Per SDM Vol 2 INVPCID instruction:

| type | meaning                                |
|------|----------------------------------------|
| 0    | Single linear address invalidation     |
| 1    | Single PCID invalidation               |
| 2    | All-context (incl. globals) invalidation|
| 3    | All-context (excl. globals) invalidation|

Wrapper module `arch::x86_64::pcid::invpcid`:

```rust
pub unsafe fn invpcid_addr(pcid: u16, addr: u64);
pub unsafe fn invpcid_single(pcid: u16);
pub unsafe fn invpcid_all_with_globals();
pub unsafe fn invpcid_all_without_globals();
```

### 3.2 aarch64 (`TLBI ASIDE1IS`)

Per Arm ARM "TLB maintenance operations":

| op            | scope                           |
|---------------|--------------------------------|
| `TLBI VMALLE1` | full TLB this CPU              |
| `TLBI VAE1IS`  | single VA + one encoded ASID, all CPUs in IS shareability |
| `TLBI VAAE1IS` | single VA + every ASID, all CPUs in IS shareability |
| `TLBI ASIDE1IS`| all entries with this ASID, all CPUs |
| `TLBI VAE1`    | single VA, this CPU            |

Wrapper module `arch::aarch64::sysreg::tlbi`:

```rust
pub unsafe fn tlbi_asid_inner_shareable(asid: u16);
pub unsafe fn tlbi_va_asid_inner_shareable(asid: u16, va: u64);
```

Each wraps `DSB ISH; ISB` for ordering.

Address-space page-table mutation uses `VAAE1IS` (or last-level
`VAALE1IS`) because the modified root may not be active on the issuing CPU.
Tag retirement uses `ASIDE1IS`; context switches do not invalidate a nonzero
lifetime tag.

## 4. Cross-CPU TLB shootdown

### 4.1 Protocol

Writer (the CPU performing the unmap):

  1. Compute the invalidation set (per-tag or per-VA).
  2. Issue the local arch-specific `INVPCID` / `TLBI`.
  3. For each peer CPU running with a stale view: send a
     **TLB-shootdown IPI** with `(tag, va_range)`.
  4. Spin until each peer ACKs.

Peer CPU IPI handler:

  1. Apply the same arch-specific invalidation.
  2. ACK via a per-CPU shootdown counter.

### 4.2 API

```rust
pub struct ShootdownRequest {
    pub tag:     Option<u16>,        // None = all-tags flush
    pub addr:    Option<u64>,        // None = full per-tag flush
    pub size:    Option<u64>,
}

pub fn shootdown(req: ShootdownRequest);
pub fn shootdown_range(tag: u16, va: u64, pages: u64);
pub fn shootdown_remote(req: ShootdownRequest);
pub fn shootdown_remote_full_for_tag(residency_tag: u16);
pub fn shootdown_target_mask(req: ShootdownRequest) -> u64;
pub fn set_active_as(cpu: u32, tag: u16);
pub fn clear_active_as(cpu: u32, tag: u16);
pub fn mark_idle(cpu: u32);
pub fn mark_busy(cpu: u32);
pub fn set_ipi_fanout(
    fanout: fn(req: ShootdownRequest, target_cpus: u64),
);
pub fn shootdown_count() -> u64;     // per-CPU counter
```

`shootdown` applies the invalidation locally and then dispatches its remote
half. `shootdown_remote` is for page-table helpers that already completed the
local half. A tracked lifetime tag publishes CPU residency before its
context-register load. Its bit is conservative history and remains set across
NOFLUSH context switches; tag retirement invalidates every CPU in that history
before reuse. Hash collisions and stale set bits can only add an IPI, never
omit one. An untracked bucket always retains bootstrap-safe all-peer dispatch.
x86 idle CPUs atomically
acquire full-flush debt instead of receiving an IPI, and `mark_busy` clears the
idle state and discharges that debt before the scheduler can load another task
root. The sender publishes debt and rechecks the idle mask, while the waking
CPU clears idle before claiming debt, so a concurrent wake is covered by either
the local full flush or the ordinary IPI rendezvous. The interrupt bridge must
publish, IPI, and await exactly the selected busy CPUs.

The pre-load residency publication is a sequentially consistent read-modify-
write. Remote dispatch executes a sequentially consistent fence after the
caller has completed its page-table writes and before it samples residency.
This forbids the store-buffer outcome where the loading CPU and invalidating
CPU each miss the other's publication. Address-space mutation and swap-out use
the tag-aware local-plus-remote surface because the edited root may be inactive
on the writer CPU; frame ownership is never released before completion.

On aarch64, tag/VA and tag-wide requests use Inner Shareable TLBI operations;
the architecture already propagates them across the shareability domain, so
the software SGI half is omitted. An untagged local `VMALLE1` request still
uses the interrupt bridge because that instruction is not shareable-scoped.

## 5. Test surface

| smoke                              | what it asserts                |
|------------------------------------|--------------------------------|
| `pcid_alloc_per_domain_unique`     | distinct domains get distinct PCIDs |
| `asid_alloc_per_domain_unique`     | aarch64 mirror                 |
| `process_contexts_are_unique_and_retired_before_reuse` | live process tags are disjoint; retirement clears ownership only after tag-wide invalidation; x86 fallback issues no tag before the all-CPU gate |
| `pcid_rollover_bumps_generation`   | rollover_now() bumps generation + invalidates |
| `invpcid_single_compiles`          | INVPCID type-1 wrapper assembles cleanly |
| `tlbi_aside1is_compiles`           | aarch64 ASIDE1IS wrapper assembles cleanly |
| `shootdown_local_only_when_up`     | shootdown() on UP exits without panic |
| `tlb_shootdown_target_mask_excludes_unselected_peer` | only selected peer ACKs a targeted request |

## 6. Out of scope (v0.1)

- `INVLPGB` / `INVLPGA` (AMD / nested-virt invalidation
  instructions).
- Hardware-assisted shootdown (Intel "Linear Address Masking" /
  "Hyper-V eager TLB" hints).
- KASLR-aware domain root cloning — kernel-half clone is
  identity today.
