# asid-pcid-isolation — Per-domain page-table isolation

> Status: **v0.1** (Stage 5 land). Supplements
> `memory/specification/spec.md` §5 with the runtime surface for
> per-domain page-table roots tagged with PCID (x86_64) / ASID
> (aarch64), the rollover allocator, and the cross-CPU TLB
> shootdown protocol.

This spec covers four primitives:

  * **Per-domain page-table root** — each NARF driver domain owns
    a private user-half PML4 (x86_64) or TTBR0 root (aarch64) so
    address-space changes don't leak across domains.
  * **ASID / PCID allocator** — generation-tagged mapping from
    `(domain_id, generation)` to a hardware tag. Rolls over when
    the architectural tag space is exhausted.
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
| x86_64  | 12 bits | 0 (reserved as "no-PCID" sentinel) | 1..4095 |
| aarch64 | 8 / 16 bits (per `ID_AA64MMFR0_EL1.ASIDBits`) | 0 (reserved as "no-ASID" sentinel) | 1..(2^N - 1) |

### 2.2 Allocation policy

The allocator hands out tags in a **generation-tagged** scheme:

  1. A monotonic per-CPU `generation` counter starts at 1.
  2. Each `(domain, generation)` pair maps to a `tag` in the
     usable space.
  3. When the tag counter exhausts the usable space, all
     `(domain, *)` mappings invalidate — every per-domain root
     gets a fresh tag in the next generation, with a global
     TLB flush issued first.
  4. The generation counter on the `PerDomainRoot` records the
     generation it was last issued at. A stale generation on
     `switch_to` triggers a re-issue + a tag-scoped TLBI before
     the CR3/TTBR write.

### 2.3 API

```rust
pub fn allocator_init();
pub fn pcid_for(domain: DomainId) -> u16;     // x86_64 (1..4095)
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
| `TLBI VAE1IS`  | single VA, all CPUs in IS shareability |
| `TLBI ASIDE1IS`| all entries with this ASID, all CPUs |
| `TLBI VAE1`    | single VA, this CPU            |

Wrapper module `arch::aarch64::sysreg::tlbi`:

```rust
pub unsafe fn tlbi_asid_inner_shareable(asid: u16);
pub unsafe fn tlbi_va_asid_inner_shareable(asid: u16, va: u64);
```

Each wraps `DSB ISH; ISB` for ordering.

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
pub fn shootdown_target_mask(req: ShootdownRequest) -> u64;
pub fn set_ipi_fanout(
    fanout: fn(req: ShootdownRequest, target_cpus: u64),
);
pub fn shootdown_count() -> u64;     // per-CPU counter
```

`shootdown` applies the invalidation locally, intersects the online-peer
mask with conservative per-CPU tag residency and the non-idle mask, then
passes that exact mask to the interrupt bridge. The bridge must publish,
IPI, and await exactly those CPUs; it must not broaden the request back to
an all-peer broadcast. `shootdown_range` represents a contiguous run as one
request and therefore one remote rendezvous.

## 5. Test surface

| smoke                              | what it asserts                |
|------------------------------------|--------------------------------|
| `pcid_alloc_per_domain_unique`     | distinct domains get distinct PCIDs |
| `asid_alloc_per_domain_unique`     | aarch64 mirror                 |
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
