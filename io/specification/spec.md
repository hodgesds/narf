# io — Specification

> Status: **v1.0** (Stage 3 design lock). v0.1 covered the
> `DmaBuffer` lifecycle + IOMMU contract; v1.0 locks the
> `Cap<DmaBuffer, _>` mint flow, the per-driver quota dimensions
> the framework consumes, ATS policy, NUMA locality, and the
> ABI versioning policy.

## 1. Purpose & scope

**Owns:** `DmaBuffer<T>` type and lifecycle, IOMMU/SMMU configuration,
per-device protection domain setup, P2P DMA topology discovery and mapping.

**Does NOT own:** Per-device MMIO access (each driver owns its own),
ring-buffer message transport (`ipc/`), interrupt delivery (`interrupts/`).

## 2. Assumptions

- `memory/` provides physically-contiguous allocation for DMA buffers.
- `capabilities/` gates DMA buffer creation: a driver needs
  `Cap<BusDevice, Dma>` to allocate and bind.
- **IOMMU presence is verified at boot by `arch/`.** Boot panics
  before any driver is loaded if the IOMMU is absent or cannot be
  programmed. This makes the "IOMMU domain ↔ CPU domain
  correspondence" invariant meaningful — we never run drivers on
  a system that cannot enforce it.

## 3. Public interface

```rust
pub struct DmaBuffer<T> { pa: PhysAddr, va: VirtAddr, size: usize, _m: PhantomData<T> }

pub fn alloc_dma<T>(n: usize, dev: &BusDevice) -> DmaBuffer<T>;

/// Coherent buffer for a device with a limited coherent DMA mask (Linux
/// `dma_set_coherent_mask` + `dma_alloc_coherent`): every byte lies at a
/// bus address `<= dma_mask`; unsatisfiable mask → `Err(NoMemory)`, never
/// an above-mask buffer. `u64::MAX` = `alloc_coherent`.
pub fn alloc_coherent_masked(len: usize, domain: DomainId, dma_mask: u64)
    -> Result<DmaBuffer, IoError>;

/// Device DMA coherence (Linux `dev_is_dma_coherent`) and reserved coherent
/// pools (Linux `kernel/dma/coherent.c`, `struct dma_coherent_mem`).
/// Module `coherent_pool`; see "Non-coherent devices" below.
pub enum DmaCoherence { Coherent, NonCoherent }
pub struct CoherentPool { /* reserved range + WC mapping + page bitmap */ }
impl CoherentPool {
    /// `rmem_dma_device_init` → `dma_init_coherent_memory`: map a no-map
    /// `shared-dma-pool` once, write-combining (aarch64 Normal-NC), shared
    /// by later callers, permanent. `PoolRejected` for empty/unaligned,
    /// overlapping or System-RAM ranges.
    pub unsafe fn reserved(phys: u64, size: u64) -> Result<Arc<Self>, IoError>;
    /// Pool over an existing caller-owned mapping (tests; not registered).
    pub unsafe fn from_mapping(phys: u64, virt: usize, size: u64)
        -> Result<Arc<Self>, IoError>;
    pub fn phys(&self) -> PhysAddr;
    pub fn virt(&self) -> usize;
    pub fn pages(&self) -> usize;
    pub fn free_pages(&self) -> usize;
}
/// `struct device` DMA facts, built by `narf_bus::dma::configure`.
pub struct DmaDevice { /* coherence + selected pool */ }
impl DmaDevice {
    pub const fn coherent() -> Self;
    /// Device pool wins; else a NonCoherent device takes the default
    /// (`linux,dma-default`) pool; a Coherent device never does.
    pub fn new(c: DmaCoherence, device_pool: Option<Arc<CoherentPool>>,
               default_pool: Option<Arc<CoherentPool>>) -> Self;
    pub fn coherence(&self) -> DmaCoherence;
    pub fn pool(&self) -> Option<&Arc<CoherentPool>>;
}
/// `dma_alloc_coherent(dev, …)`: pool → `__dma_alloc_from_coherent`
/// (zeroed, naturally aligned power-of-two page run, `<= dma_mask`);
/// Coherent without pool → exactly `alloc_coherent_masked`; NonCoherent
/// without pool → `Err(NoCoherentPool)`.
pub fn alloc_coherent_for(dev: &DmaDevice, len: usize, domain: DomainId,
                          dma_mask: u64) -> Result<DmaBuffer, IoError>;
impl DmaBuffer {
    /// Pool buffers resolve `cpu_ptr*`/`as_slice` through the pool mapping.
    pub fn is_pool_backed(&self) -> bool;
    /// Streaming maintenance, Linux `arch_sync_dma_for_device` (clean,
    /// direction ignored) / `arch_sync_dma_for_cpu` (nothing for ToDevice,
    /// else `dcache_inval_poc`: civac partial edge lines, ivac whole lines).
    /// x86_64 flushes (CLFLUSH) in both. `sync` stays clean+invalidate.
    pub fn sync_for_device(&self, offset: usize, len: usize, dir: DmaDirection);
    pub fn sync_for_cpu(&self, offset: usize, len: usize, dir: DmaDirection);
}
pub enum DmaDirection { Bidirectional, ToDevice, FromDevice }
pub enum IoError { /* … */ NoCoherentPool, PoolRejected }

/// Bounded recycler for one hardware RX or TX queue. Construct, `prepare`,
/// and `prefill` it before the queue is made live. `try_acquire` and
/// `release` are the packet/completion-path API: neither may allocate.
pub struct DmaPool { /* fixed-length coherent-buffer recycler */ }
pub struct DmaPoolStats {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub recycle_drops: u64,
}
impl DmaPool {
    pub const fn new(buf_len: usize, domain: DomainId, cap: usize) -> Self;
    pub fn prepare(&self) -> bool;
    pub fn prefill(&self, n: usize) -> usize;
    pub fn try_acquire(&self) -> Option<DmaBuffer>;
    pub fn try_acquire_batch(&self, out: &mut [Option<DmaBuffer>]) -> usize;
    pub fn release(&self, buf: DmaBuffer);
    pub fn release_batch(&self, bufs: &mut [Option<DmaBuffer>]) -> usize;
    /// Setup/recovery only: may allocate when the recycler is empty.
    pub fn acquire(&self) -> Option<DmaBuffer>;
    pub fn stats(&self) -> DmaPoolStats;
}

pub fn map_p2p(src: &BusDevice, dst: &BusDevice, buf: &DmaBuffer<T>)
    -> Result<P2pBinding, IoError>;

/// Tear down a P2P binding. Quiescence protocol (binding):
/// 1. Notify both drivers' domains of pending teardown via `tracing/` event.
/// 2. Invalidate both sides' IOMMU TLB entries for the binding's IOVA range.
/// 3. Wait for in-flight DMA to complete — either by IOMMU drain
///    (preferred where supported: VT-d `IOTLB_INVALIDATE` + Drain Wait;
///    SMMUv3 `CMD_TLBI_NSNH_ALL` + `CMD_SYNC`), or by a
///    device-activity timeout (default 100 ms).
/// 4. Release the binding's resources.
/// Returns only after step 4 completes.
pub fn unmap_p2p(binding: P2pBinding) -> impl Future<Output = ()>;

/// Per-domain IOMMU fault handler. The driver framework registers
/// one of these per driver domain; `io/` invokes it on every fault
/// the IOMMU reports for that domain (drained from the hardware
/// fault log: VT-d Fault Recording, AMD-Vi Event Log, SMMUv3
/// PRIQ / EVTQ). In Stage 3 the default is log-and-continue; in
/// Stage 4 a fault rate exceeding a per-driver threshold escalates
/// to driver termination.
pub type IoFaultHandler = fn(&BusDevice, IoFault);
pub fn register_fault_handler(dev: &BusDevice, h: IoFaultHandler);
```

IOMMU: each driver gets its own IOMMU context so a malicious device
cannot DMA outside the buffers its driver explicitly mapped.

**Non-coherent devices.** `alloc_coherent*` returns write-back RAM through
the direct map; that is coherent only on a snooping interconnect (all
x86_64, QEMU `virt`). Linux arm64 remaps RAM Normal-NC for a non-snooping
device (`DMA_DIRECT_REMAP`); NARF never aliases System RAM non-write-back
(`memory/src/memtype.rs`), so such a device allocates from a firmware
reserved `no-map` `shared-dma-pool` instead (its own `memory-region`, else
`linux,dma-default`), mapped through `narf_memory::ioremap` with
`MmioAttrs::WriteCombining`. No pool → `NoCoherentPool` (fail closed).
Pools are permanent (the ioremap cache shares identical mappings, so
tearing one down would revoke it from every user). On aarch64 the boot
linear window still maps the low RAM GiB write-back in 2 MiB blocks; a pool
inside it keeps that cacheable alias (the same residual Linux accepts for
`DMA_DIRECT_REMAP`), so pool creation cleans+invalidates the range by VA
(`arch_dma_prep_coherent`), and nothing in the kernel touches the alias.
Removing `no-map` ranges from the linear map is a `memory/` change.

**Scatter-gather page lists** (`io/src/sg.rs`, Linux `struct bio_vec` /
`sg_table` as a device sees it). `PageList::new(pages: Vec<PhysAddr>, len,
domain)` names order-0 frames the caller owns (page-cache pages, a
filesystem's node buffers) carrying `len` bytes; `segments()` /
`segments_in(offset, len)` return `(dma, len)` runs with physically adjacent
frames merged. `register_pages_with_cap(list) -> Cap<PageList, Write>` mints
a `CapKind::DmaPageList` capability in the same epoch-gated registry as
`DmaBuffer`; `resolve_pages_cap(&Cap<PageList, R>)` resolves it (a revoked
cap resolves to nothing) and `unregister_pages(cap)` revokes it — the list
lives until the last `Arc` drops, i.e. after every command in flight over it
completed. In per-domain IOMMU mode `PageList::map_into(&domain, pci)` maps
every frame read/write into the device's domain (`dma_addr(i)` becomes the
IOVA) and the mappings are torn down when the list drops; identity /
disabled modes use the frame address. The frames themselves are never freed
by `io/`: they are the caller's, kept allocated for the list's lifetime.
`unregister_pages` / `unregister` clear the registry slot and then
`object_table::release` the index, so a caller with a payload per block
request (a filesystem's every read and write) does not grow the object table
or this registry: the index is handed to a later registration under a greater
generation, and every copy of the old cap — a split child, a request a device
still owns after a timeout, a killed waiter's abandoned request — fails
`check_live` instead of resolving to the new payload
(`smoke_io_registry_bounded_by_live_objects`).

**Per-domain IOMMU translation** (module `iommu`, `iova`; Linux
`iommu.c` + `dma-iommu.c` + `iova.c` + `generic_pt/fmt/{amdv1,vtdss}.h`).

```rust
pub enum PageTableFormat { AmdV1, VtdSecondStage }   // 4-level, 48-bit IOVA
pub trait IommuHw: Send + Sync {                      // one per unit type
    fn name(&self) -> &'static str;
    fn format(&self) -> PageTableFormat;
    fn coherent_walk(&self) -> bool;                  // else PTE stores are cleaned
    fn attach(&self, bdf: Bdf, domain_id: u16, root: u64, levels: u8) -> Result<(), IoError>;
    fn detach(&self, bdf: Bdf, domain_id: u16) -> Result<(), IoError>;
    /// Invalidate + completion wait; Ok = no cached translation survives.
    fn flush_iotlb(&self, domain_id: u16, iova: u64, len: u64) -> Result<(), IoError>;
    fn sync_map(&self, domain_id: u16, iova: u64, len: u64) -> Result<(), IoError>; // default Ok
    /// IVMD unity / RMRR ranges; attach maps them 1:1 first. Default empty.
    fn direct_mappings(&self, bdf: Bdf) -> Vec<DirectMapping>;
}
pub struct DirectMapping { pub start: u64, pub end: u64, pub perms: IommuPerms } // [start, end)
pub enum IoError { /* … */ Timeout }              // invalidation did not complete
pub const PER_DOMAIN_CMDLINE_KEY: &str = "iommu.passthrough";
pub fn per_domain_requested_in(cmdline: &str) -> bool; // "0" | "n" | "N" | "off"
pub enum PerDomainOptIn { Unknown, NotRequested, Enabled, NoBackend,
                          DmaAlreadyHandedOut, AlreadyPerDomain, Failed(amd_vi::EnableError) }
pub fn per_domain_opt_in() -> PerDomainOptIn;
pub fn enable_per_domain(hw: &'static dyn IommuHw) -> Result<(), IoError>; // → IommuMode::PerDomain
pub fn default_domain(bdf: Bdf) -> Result<Arc<IommuDomain>, IoError>;     // iommu_get_dma_domain
pub fn release_default_domain(bdf: Bdf) -> Result<(), IoError>;
pub enum DmaBlock { Untranslated, Blocked }
pub fn block_device_dma(bdf: Bdf) -> Result<DmaBlock, IoError>;  // pci_dev_reset_iommu_prepare
pub fn restore_device_dma(bdf: Bdf) -> Result<(), IoError>;       // pci_dev_reset_iommu_done
pub fn device_dma_blocked(bdf: Bdf) -> bool;
pub fn walk(format: PageTableFormat, root: u64, iova: u64) -> Option<u64>; // software walk
impl IommuDomain {
    pub fn attach(&self, bdf: Bdf) -> Result<(), IoError>;  // exclusive: DomainMismatch if attached elsewhere
    pub fn detach(&self, bdf: Bdf) -> Result<(), IoError>;
    pub fn map(&self, iova: u64, phys: u64, len: u64, perms: IommuPerms) -> Result<u64, IoError>;
    pub fn map_below(&self, phys: u64, len: u64, perms: IommuPerms, dma_mask: u64, pci: bool)
        -> Result<u64, IoError>;                              // iommu_dma_alloc_iova (PCI: 32-bit first)
    pub fn unmap(&self, iova: u64, len: u64) -> Result<(), IoError>;
    pub fn translate(&self, iova: u64) -> Option<(u64, IommuPerms)>;
    pub fn page_table_root(&self) -> Option<(PageTableFormat, u64)>;
    pub fn quarantined_pages(&self) -> u64;
}
pub struct IovaAllocator;  // new / reserve / alloc(pages, limit_pfn, size_aligned) /
                           // alloc_fixed / free / quarantine
impl DmaDevice { pub fn with_iommu_domain(self, d: Arc<IommuDomain>) -> Self;
                 pub fn iommu_domain(&self) -> Option<&Arc<IommuDomain>>; }
impl DmaBuffer { pub fn iommu_domain_id(&self) -> Option<u16>; }
```

In `PerDomain`, `alloc_coherent_for(dev, ..)` with a domain allocates frames
anywhere, maps them read/write at a size-aligned top-down IOVA `<= dma_mask`
(32-bit tried first: Linux PCI SAC behaviour) and `DmaBuffer::dma_addr()`
returns the IOVA; `phys_addr()` stays physical. A device without a domain is
`NotMapped`, as are device-less `map_phys` / `unmap_iova`.
`narf_bus::dma::configure` attaches a PCI function (segment 0) to its default
domain. Domain IDs start at 1 and are never recycled. Each domain reserves
the x86 interrupt window `0xfee0_0000..=0xfeef_ffff` (and, for AMD v1, the
HyperTransport window `0xfd_0000_0000..=0xff_ffff_ffff`). Intermediate
tables live until the domain is destroyed; a domain dropped with devices
still attached leaks its tables. `iommu_model::ModelIommu` is a recording
software backend for tests only (`set_fail_flush` / `set_fail_detach`
inject invalidation timeouts).

**Device DMA quiescence.** `block_device_dma` is the driver-neutral way to
stop a device's DMA before releasing memory it may still reach (Linux
blocking domain: `pci_dev_reset_iommu_prepare`, and the blocked release
domain on removal). Outside `PerDomain` it is `Untranslated` and touches no
hardware: DMA addresses are physical and the caller's device-side evidence
is the only proof. In `PerDomain` it detaches the device from its default
domain, which per the `IommuHw::detach` contract returns only after the
blocking DTE/context entry and the device-entry + domain IOTLB invalidation
completed; the default domain stays recorded, so buffers still mapped there
unmap with the usual strict invalidate → wait → free ordering. A device with
a default domain but no attachment is reported `Blocked` (idempotent; a
never-attached AMD-Vi requester passes through, so "no default domain" is
`NotMapped`, never blocked). A detach error (`Timeout`) means the device may
still translate. `restore_device_dma` re-attaches the retained default
domain (`pci_dev_reset_iommu_done`) and must only be called by the holder of
the device's own stop/reset proof. Users: brcmfmac PCIe
(`drivers/wireless/specification/brcmfmac.md` "IOMMU-backed quiescence").

**AMD-Vi silicon backend** (module `amd_vi`, Linux
`drivers/iommu/amd/{init.c,iommu.c,amd_iommu_types.h}`):

```rust
pub mod amd_vi {
    pub mod ivrs {                       // init_iommu_from_acpi / init_memory_definitions
        pub fn parse(table: &[u8]) -> Result<IvrsInfo, IvrsError>;
        pub struct IvrsInfo { iv_info, ivhd_type, units: Vec<IvhdUnit>, unity: Vec<UnityRange> }
        pub struct IvhdUnit { ivhd_type, flags, devid, cap_ptr, mmio_phys, pci_seg, info,
                              efr_attr, efr_reg, devices: Vec<DevRange>,
                              aliases: Vec<AliasRange>, specials: Vec<SpecialDevice>,
                              acpi_hids: Vec<AcpiHidDevice> }
    }
    pub trait AmdViRegs: Send + Sync { fn read64; fn write64; fn read32; fn write32; }
    pub struct MmioRegs;                 // ioremap(Device) of the 16 KiB register block
    pub fn bring_up(info: &IvrsInfo, map: &dyn Fn(&IvhdUnit) -> Option<Box<dyn AmdViRegs>>)
        -> Result<AmdVi, BringUpError>;
    pub struct AmdVi;                    // impl IommuHw; poll_events / event_count /
                                         // recent_events / read_dte / unit_rings / alias_of
    pub fn boot_enable() -> Result<&'static AmdVi, EnableError>; // used by iommu::init
    pub fn active() -> Option<&'static AmdVi>;
    pub fn poll_events() -> usize;
    // Linux-exact encoders: cmd_completion_wait, cmd_inv_dte, cmd_inv_iommu_pages,
    // cmd_inv_all, build_inv_address, dte_initial / dte_passthrough / dte_blocked /
    // dte_translated.
}
```

- **Opt-in only.** `init` keeps selecting `Identity` and never touches
  IOMMU hardware configuration unless the kernel command line carries
  `iommu.passthrough=0` (Linux's switch for DMA-translated default
  domains). Then, on an AMD-Vi platform where no DMA address has yet been
  handed out (`alloc_with` / `alloc_coherent_for` set a gate), `init`
  runs `amd_vi::boot_enable` and `enable_per_domain`; otherwise it stays
  `Identity` and `per_domain_opt_in()` says why. Today `frame/` calls
  `init` after the initcall stages have probed drivers, so the opt-in
  reports `DmaAlreadyHandedOut` until `frame/` calls `init` before the
  initcalls (a TCB change, pending maintainer review).
  Without opt-in it logs inherited AMD-Vi control and device-table-base
  registers for each IVRS unit without writes or firmware-table dereferences.
  Each diagnostic window uses the backend's checked Device mapping; it must
  not derive MMIO pointers from the RAM direct-map offset. An unavailable
  diagnostic mapping is logged and skipped without preventing normal boot.
  The software `Identity` mode alone does not prove firmware translation was
  disabled or programmed as passthrough.
- **IVRS.** Linux `get_highest_supported_ivhd_type`: only IVHD blocks of
  the highest supported type are used. Device entries 01h/02h/03h/04h/
  42h/43h/46h/47h/48h(IOAPIC, HPET)/F0h give the requester-ID → unit
  lookup, aliases and the IVHD DTE setting flags (first range wins). IVMD
  20h/21h/22h with the unity or exclusion flag become direct mappings
  (exclusion = read/write unity, as Linux). Units outside PCI segment 0
  are ignored (`narf_bus::dma::configure` only attaches segment 0).
- **Device table.** One 2 MiB (65 536 × 32 B) order-9 block shared by the
  segment's units; base register = `phys | 0x1ff`. Every DTE starts as
  Linux's identity entry (`set_dte_passthrough`: `V|TV|IR|IW`, `Mode 0`,
  domain 0) plus IVHD flag bits (erratum 63: SysMgt = 01b ⇒ `IW`), so an
  unattached device DMAs untranslated. Attach writes the v1 entry
  (`TV`, `Mode = levels`, root[51:12], `IR|IW`, domain ID) for the device
  and its alias (`clone_aliases`); requesters sharing an alias must share
  a domain. Detach follows the trait contract and **blocks**
  (`V|TV`, `Mode 0`, no `IR`/`IW`) once the last user of a requester ID
  leaves. DTE updates go upper half → blocking low quadword → domain ID →
  new low quadword (Linux uses one `cmpxchg16b`). A requester no IVHD
  covers is refused (`NotMapped`).
- **Commands.** 512-entry ring, `COMPLETION_WAIT` storing a monotonic
  sequence number to a per-unit semaphore page, polled for 100 ms
  (Linux `LOOP_TIMEOUT`); failure is `IoError::Timeout`, which makes
  `IommuDomain` quarantine the IOVA and leak the frames. Attach =
  `INVALIDATE_DEVTAB_ENTRY`(+alias) + wait; detach = those +
  `INVALIDATE_IOMMU_PAGES` (domain, all, `PDE`) + wait; unmap =
  `INVALIDATE_IOMMU_PAGES` with Linux's `build_inv_address` size encoding +
  wait on every segment-0 unit. An attach whose wait fails leaves the
  device blocked. ATS is never enabled, so `INVALIDATE_IOTLB_PAGES` is
  never sent.
- **Enable sequence** per unit (`early_enable_iommu`): `iommu_disable`
  (CmdBufEn, EvtIntEn, EvtLogEn, GALogEn, GAIntEn, PPRLogEn, PPRIntEn,
  IommuEn, IRTCacheDis cleared) → `iommu_init_flags` (HtTunEn / PassPW /
  ResPassPW / Isoc from the IVHD flags, Coherent, InvTimeout = 1 s) →
  device-table base → command buffer + head/tail reset + CmdBufEn →
  IommuEn → `INVALIDATE_IOMMU_ALL` (EFR.IA) or per-DTE + per-domain
  invalidation → event log (512 entries) + EvtLogEn. A failure disables
  the units again before the tables are freed.
- **Event log** is polled (no MSI) after every command wait and by
  `amd_vi::poll_events`: per-type counters (IO_PAGE_FAULT = type 2), the
  last 16 decoded events, Linux's erratum-732 zero-entry retry and
  overflow restart (`amd_iommu_restart_event_logging`).
- **Not enabled:** interrupt remapping (DTE `IV`/`IntCtl` = 0: MSIs and
  IOAPIC/HPET interrupts pass through untranslated; no IRT, GA, XT,
  2K-IRTE), ATS, PPR/EPH, guest translation, SNP, the event interrupt.
  Linux's AMD-Vi errata code targets family 15h (746, ATS write check) or
  SNP systems; nothing applies to family 17h (Renoir) / 19h (Phoenix)
  beyond erratum 63 / 732 handling above.
- **Validation status.** Only kernel-test smokes against a register model
  (`io/iommu/amdvi`) exist, written and not yet executed. Native
  validation needs QEMU's emulated AMD IOMMU, e.g.
  `qemu-system-x86_64 -machine q35 -device amd-iommu,intremap=off
  -device <endpoint> … -append "… iommu.passthrough=0"` (`amd-iommu` must
  precede the PCI endpoints; QEMU then publishes the IVRS), plus the
  `frame/` change that calls `iommu::init` before the initcalls. No AMD-Vi silicon has run this code. VT-d
  (context tables + queued invalidation) and SMMUv3 (STE + CMDQ
  `CMD_SYNC`) backends are open work.

`DmaPool` is deliberately per queue, rather than a global allocator cache:
that maintains NUMA/device affinity and prevents unrelated RX/TX completion
cores from contending on a shared recycler. The hot path treats an empty pool
as bounded backpressure; only queue setup or a refill/recovery worker may call
the allocating APIs.

## 4. Invariants & safety properties

- A `DmaBuffer<T>` is pinned in physical memory for its lifetime.
- **CPU-domain ↔ IOMMU-domain correspondence is enforced at
  `alloc_dma` call time**: `dev`'s IOMMU domain ID is verified to
  equal the calling task's `DomainId`; mismatch is a panic, not a
  return value. Without this runtime check the correspondence is
  aspirational, not load-bearing.
- Per-domain unmap is strict: PTEs cleared → `IommuHw::flush_iotlb`
  (invalidate + completion wait) → IOVA freed → frames freed. A failed
  flush quarantines the IOVA and leaks the frames (`DmaBuffer` drop);
  neither is reused while a stale translation may exist.
- Dropping a `DmaBuffer` tears down the IOMMU mapping before freeing
  physical storage. **IOTLB invalidation must complete before
  `PhysFrame` is returned to `memory/`.** Completion mechanism:
  VT-d uses `IOTLB_INVALIDATE` + poll `IOTLB_CTRL.IVT` bit;
  SMMUv3 uses a `CMD_TLBI_*` + `CMD_SYNC` polling
  `GERROR.SYNC_ERR`. Without explicit completion polling, a stale
  IOTLB entry could let a freed frame still be DMA-targeted.
- **DMA-buffer and P2P-binding access always goes through `Cap::invoke`**
  (see `capabilities/` §3). When a driver's `Cap<BusDevice, Dma>` is
  revoked, the object epoch bumps; outstanding `DmaBuffer` caps fail
  on next use, the IOMMU mapping is torn down by the reclamation
  path, and any in-flight DMA is quiesced per `drivers/` §3 quiesce
  protocol. Prior authorisation (holding the `Cap`) is not current
  validity.
- **`DmaBuffer` follows the `abi/` cancellation protocol.** A DMA
  buffer submitted as the target of an in-flight operation is
  conceptually borrowed by the device until the submission's
  terminal completion drains. The buffer is freed only on
  `Ok | Cancelled | Error`. Dropping the Future *requests*
  cancellation via `OpCode::Cancel(tag)`; the kernel then either
  (a) aborts the DMA (device-specific — NVMe Abort, virtio
  descriptor reclaim), or (b) waits for hardware completion, then
  returns `Cancelled` with any durable effect reported in `result`.
  Freeing a `DmaBuffer` whose device has not yielded a terminal
  completion is a UAF — the spec forbids it and debug builds
  assert. See `abi/` §3.1.
- A `DmaPool` receives a buffer only after that buffer's device ownership has
  ended at a validated RX/TX terminal completion. A driver never recycles a
  buffer still described by a live hardware descriptor.
- Queue setup calls `prepare` before enabling IRQ/NAPI-like poll work. The
  packet and completion path uses only `try_acquire` / `release` (or their
  batch forms): they do not allocate, resize metadata, or fall back to the
  buddy/slab allocator. A full or unprepared recycler drops its returned
  buffer only after releasing its queue-local lock; an empty recycler reports
  backpressure.

## 5. Architecture notes

### x86_64
- IOMMU: Intel VT-d or AMD-Vi; we configure per-device context entries.
- P2P DMA: requires ACS on the PCIe root port(s) between peers, or
  explicit ATS/PRI.

### aarch64
- IOMMU: Arm SMMUv3 via the streaming model; StreamID per device.
- **StreamID discovery is via ACPI IORT** (on SystemReady boards) or
  devicetree `iommus` property; `bus/` exposes a StreamID lookup by
  BDF. NARF does not synthesize StreamIDs — they are device-tree
  facts.
- DMA coherency: `narf_bus::dma::configure` reads `dma-coherent` /
  `dma-noncoherent` (host bridge node for PCI); non-coherent devices use
  `alloc_coherent_for` and a reserved Normal-NC pool (§3). Non-coherent
  paths require cache maintenance around buffer use. **Ownership of
  these `DC CIVAC` operations belongs to `DmaBuffer<T>` lifecycle
  methods** (one before device handoff, one after device completion).
  Drivers do not invoke cache maintenance directly.

## 6. Dependencies

- **Consumes:** `memory/`, `capabilities/`, `arch/`.
- **Provides to:** every device driver; `ipc/` for cross-domain shared
  buffers (in the P2P-on-same-host sense, not PCIe P2P).

## 7. Stage assignment

Stage 3.

## 8. Capability surface

```rust
pub struct DmaBuffer;        // CapKind::DmaBuffer
pub struct IommuContext;     // internal — per-driver IOMMU domain handle
```

The driver framework mints `Cap<DmaBuffer, _>` at allocation
time, with the cap's badge encoding:

- The bound `BusDevice` (which device owns this DMA target).
- The mapped `DomainId` (CPU-side domain that may access the
  buffer).
- The IOVA range (which sub-range of the device's IOVA space).

Revocation (driver unload, fault-rate escalation, manual
revoke) bumps the cap's epoch; subsequent `read`/`write` to the
buffer fail with `Err(Revoked)`. The IOMMU teardown then
follows the §4 invariants — IOTLB invalidate before frame
return.

### 8.1 Allocation API

```rust
pub fn alloc_coherent(
    n:   usize,
    dev: &Cap<BusDevice, Dma>,
    quota: &Cap<Quota, Spend>,
) -> Result<Cap<DmaBuffer, Read | Write>, IoError>;

pub fn alloc_streaming(
    n:    usize,
    dev:  &Cap<BusDevice, Dma>,
    dir:  Direction,                // ToDevice | FromDevice | Bidirectional
    quota: &Cap<Quota, Spend>,
) -> Result<Cap<DmaBuffer, /* dir-tagged rights */>, IoError>;
```

`alloc_coherent` is for ring/control structures — coherent
across the CPU/device boundary, no cache maintenance needed.
`alloc_streaming` is for transient payload buffers — needs
explicit pre/post-DMA cache maintenance on aarch64
non-coherent paths (handled by `DmaBuffer` lifecycle, drivers
never call cache ops directly per §5 aarch64).

Both charge the calling driver's `Cap<Quota, Spend>` against
the `max_dma_bytes` and `max_dma_buffers` dimensions
(`drivers/spec` §17.2). Exhaustion → `Err(QuotaExceeded)`.

## 9. Resolved decisions

### 9.1 ATS mandate (resolved)

**Decision (was open):** ATS is **not mandated**. Drivers and
NARF run on platforms with or without ATS. The IOMMU is
mandated (see §2); ATS is an optional optimization.

A driver that wants to use ATS does so via an opt-in cap
operation:

```rust
fn enable_ats(dev: &Cap<BusDevice, _>) -> Result<Cap<AtsContext, _>, IoError>;
```

ATS-enabled drivers see lower DMA latency on platforms that
support it; the same driver code falls back to non-ATS DMA
otherwise. The op queries the device's PCIe ATS capability
and the IOMMU's ATS support; missing either → `Err(NotSupported)`.

This avoids the platform-availability problem of mandating ATS
(many embedded aarch64 platforms don't have it) while still
letting hot-path drivers (NVMe, RDMA NICs) opt in for the
performance win where available.

### 9.2 Non-coherent cache flush ownership (resolved)

**Decision (was open):** **`DmaBuffer<T>` lifecycle methods
own all cache maintenance**, transparently to drivers. The
driver writes payload, calls `buf.before_device_use()` (or
`alloc_streaming`'s implicit handoff), the device DMAs, and on
completion the driver calls `buf.after_device_use()` (or the
implicit reclamation path).

Cost attribution: the cache-flush op runs in the **driver's
domain context**, not in `io/`. So the driver's `Cap<Quota,
Spend>` could in principle account it; in v1.0 we don't —
cache ops are too cheap to bother metering. Revisit if a
pathological non-coherent platform shows otherwise.

x86_64 is fully coherent for DMA; these methods are no-ops.
aarch64 with `dma-coherent` in DT is also no-op. Only legacy
or constrained aarch64 platforms (some embedded SoCs) pay the
cost.

### 9.3 NUMA locality (resolved)

**Decision (was open):** DMA buffers are NUMA-locality-aware
via the `BusDevice`'s `numa: Option<NumaNodeId>` field.
`alloc_coherent` and `alloc_streaming` allocate from the
device's home node when possible; if the home node is
exhausted, fall back round-robin to other nodes (with a
`tracing/` event noting the fallback for observability).

The fallback is per-allocation, not per-driver. A device
pinned to NUMA node 1 with node 1 exhausted gets node 0
buffers transparently; performance suffers but correctness
holds.

The `bus/` layer is responsible for populating
`BusDevice::numa` from ACPI SRAT (x86_64) or DT
`numa-node-id` (aarch64). Devices without NUMA metadata
default to "any node" allocation.

## 10. Per-driver IOMMU domain

Each driver instance receives a `Cap<IommuContext, Read>` at
BIND time alongside the rest of its cap bundle. The IOMMU
context corresponds to a **dedicated IOMMU domain ID** on the
hardware:

- VT-d: a context entry distinct from any other driver's.
- SMMUv3: a distinct StreamID-to-domain mapping (multiple
  StreamIDs may map into the same domain when one driver owns
  multiple devices).

The per-driver IOMMU domain enforces **inter-driver isolation
even at the DMA level** — a compromised driver cannot DMA into
another driver's memory regardless of what BAR/DMA addresses
it forges, because the IOMMU rejects the access.

This is the IOMMU-side of the CPU domain isolation in
`security-model/` §4.1: caps + domains + IOMMU = three
independent layers a compromise must defeat.

## 11. Fault handling

`IoFault` is the unified type across VT-d / AMD-Vi / SMMUv3:

```rust
pub struct IoFault {
    pub kind:     FaultKind,        // PageFault | InvalidContext | TimeOut | ...
    pub iova:     u64,              // faulting IOVA
    pub stream:   u32,              // bus device id (BDF or StreamID)
    pub access:   AccessType,       // Read | Write | Execute (where applicable)
}
```

Per-driver fault handlers are installed via §3
`register_fault_handler`. The framework's default policy
(installed automatically at BIND if the driver doesn't supply
one):

```rust
fn default_io_fault_handler(dev: &BusDevice, fault: IoFault) {
    record_to_tracing_ring(dev, &fault);
    bump_per_instance_fault_counter(dev);
    if rate_exceeds_threshold(dev) {
        request_driver_unload(dev, UnloadReason::IoFaultStorm);
    }
}
```

The threshold is per-driver-instance (manifest-configurable
defaults: 100 faults/second sustained for 10 seconds → unload).

## 12. ABI versioning

`io/` exports are tagged at `@v0` in the SDK. The wire
contracts:

- `DmaBuffer` cap badge layout (BusDevice id + DomainId + IOVA
  range) is part of the cap-ABI; changes follow `CAP_ABI_MAJOR`.
- `IoFault` struct layout is part of the SDK ABI; field
  additions are minor bumps; renumbering kinds is a major.
- Allocation APIs (`alloc_coherent`, `alloc_streaming`) are
  versioned per-symbol; an `alloc_coherent@v1` adding a
  `flags: AllocFlags` argument would ship alongside `@v0`.

Currently `IO_ABI_MAJOR = 1`, `IO_ABI_MINOR = 0`.

## 13. Open questions

(none — all v0.1 questions resolved in §9)
