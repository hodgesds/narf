# iommu-interconnect — Tier-8 IOMMU + cross-CPU interconnect

> Status: **v0.1**. Locks the surface for the IOMMU register
> layouts and the x86_64 RAR fast-shootdown doorbell. Higher-
> level IOMMU bring-up (root-table allocation, context-entry
> programming, fault-handling pipeline) lives in `bus/` and
> `memory/` follow-ups; this batch covers the per-arch
> register layout + caps decode that those crates rely on.

For x86_64:

  * **Intel VT-d** — DMA Remapping. Per-engine MMIO register
    block; `CAP_REG`/`ECAP_REG` decode + global-command/
    status surface.
  * **AMD-Vi** — IOMMU. PCI capability-discovered MMIO block;
    Capability-header + Extended-Feature register decode +
    global-control surface.
  * **RAR** — Remote Action Request. Per-CPU MMIO doorbell
    that delivers TLB shootdowns + remote-cpuid actions
    without an IPI vector. Sapphire Rapids+.

For aarch64:

  * **SMMUv3** — Arm System MMU. MMIO register block;
    IDR0..IDR5 + caps decode + GBPA / CR0 / GBPA control.

## 1. Intel VT-d

### 1.1 Register block

The VT-d register block is enumerated via the ACPI DMAR table.
Each engine's base address sits at `RegBase` and the relevant
v0.1 offsets are:

| offset  | name      | content                                          |
|---------|-----------|--------------------------------------------------|
| `0x00`  | VER_REG   | version (Major[7:4] / Minor[3:0])                |
| `0x08`  | CAP_REG   | capabilities (64-bit)                            |
| `0x10`  | ECAP_REG  | extended capabilities (64-bit)                   |
| `0x18`  | GCMD_REG  | global command (write-only)                      |
| `0x1C`  | GSTS_REG  | global status                                    |
| `0x20`  | RTADDR_REG | root-table address (64-bit)                     |
| `0x28`  | CCMD_REG  | context-cache command (64-bit)                   |
| `0x40`  | FSTS_REG  | fault status                                     |
| `0x44`  | FECTL_REG | fault-event control                              |
| `0x60`  | PMEN_REG  | protected memory enable                          |

`CAP_REG` shape (selected fields):

| bits   | field                                            |
|--------|--------------------------------------------------|
| 2:0    | ND — number of domains supported                  |
| 7      | AFL — advanced fault logging                     |
| 8      | RWBF — required write-buffer flushing            |
| 16:10  | SAGAW — supported adjusted guest addr widths     |
| 39:24  | NFR — number of fault-recording regs             |
| 53:48  | DRD — direct-route descriptors                   |

`GCMD` / `GSTS` mirror bits:

| bit | name | meaning                              |
|-----|------|--------------------------------------|
| 31  | TE   | translation enable (CMD set / STS reflects) |
| 30  | SRTP | set root-table pointer               |
| 29  | SFL  | set fault-log                        |
| 28  | EAFL | enable advanced fault logging        |
| 27  | WBF  | write-buffer flush                   |
| 26  | QIE  | queued-invalidation enable           |
| 25  | IRE  | interrupt-remapping enable           |
| 24  | SIRTP| set interrupt-remap-table pointer     |

### 1.2 API

```rust
pub struct VtdCaps {
    pub version_major: u8,
    pub version_minor: u8,
    pub num_domains:   u32,
    pub sagaw:         u8,
    pub num_fault_regs: u16,
    pub queued_invalidation: bool,
    pub interrupt_remap: bool,
}

pub unsafe fn read_caps(reg_base: usize) -> VtdCaps;
pub unsafe fn read_gsts(reg_base: usize) -> u32;
pub unsafe fn write_gcmd(reg_base: usize, bits: u32);
pub unsafe fn write_rtaddr(reg_base: usize, paddr: u64);
```

## 2. AMD-Vi

### 2.1 Capability discovery

AMD-Vi engines register themselves as a PCI capability of type
`0x0F` ("Secure Device") at the host bridge. The capability
header carries the IOMMU base-address-register pointer; the
v0.1 layout we surface is the MMIO block at that base:

| offset   | name              | content                          |
|----------|-------------------|----------------------------------|
| `0x00`   | DEV_TAB_BASE      | device table base + size encoding |
| `0x08`   | CMD_BUF_BASE      | command buffer base               |
| `0x10`   | EVT_LOG_BASE      | event log base                    |
| `0x18`   | IOMMU_CTRL        | control register                  |
| `0x30`   | EXT_FEATURES      | extended features (64-bit)        |
| `0x40`   | PPR_LOG_BASE      | PPR log base                      |

`IOMMU_CTRL`:

| bit | name            | meaning                                |
|-----|-----------------|----------------------------------------|
| 0   | IOMMUEN         | enable                                 |
| 1   | HTTUNEN         | HyperTransport tunnel enable           |
| 2   | EVTLOGEN        | event log enable                       |
| 3   | EVTINTEN        | event interrupt enable                 |
| 4   | COMWAITINTEN    | completion-wait interrupt enable       |
| 8   | CMDBUFEN        | command buffer enable                  |
| 12  | PPRLOGEN        | PPR log enable                         |

`EXT_FEATURES` selected bits:

| bit | name        |
|-----|-------------|
| 0   | PREFSUP     |
| 1   | PPRSUP      |
| 2   | XTSUP       |
| 4   | NXSUP       |
| 5   | GTSUP       |
| 7   | IASUP       |
| 8   | GASUP       |

### 2.2 API

```rust
pub struct AmdViCaps {
    pub iommu_enabled:       bool,
    pub event_log_enabled:   bool,
    pub command_buf_enabled: bool,
    pub ppr_supported:       bool,
    pub gt_supported:        bool,
    pub xts_supported:       bool,
}

pub unsafe fn read_caps(reg_base: usize) -> AmdViCaps;
pub unsafe fn read_ctrl(reg_base: usize) -> u64;
pub unsafe fn write_ctrl(reg_base: usize, value: u64);
```

## 3. x86_64 RAR

### 3.1 Detection

CPUID(7, 1).EAX[31] = `RAR` (Remote Action Request).
Per-CPU MMIO base programmed via `IA32_RAR_INFO_BASE`
(`0x1024`). The doorbell is written with a packed
`{action, target_lpid, payload}` triple; hardware delivers
the action to the target CPU without an IPI vector.

### 3.2 MSRs

| MSR     | name              | content                              |
|---------|-------------------|--------------------------------------|
| `0x1024`| IA32_RAR_INFO_BASE| MMIO base + caps                     |
| `0x1025`| IA32_RAR_CTRL     | enable / mask                        |

### 3.3 Actions

| action-id | meaning                       |
|-----------|-------------------------------|
| `0x00`    | TLB shootdown (single page)   |
| `0x01`    | TLB shootdown (full mm)        |
| `0x02`    | RDPMC remote                   |
| `0x03`    | invd remote                    |

### 3.4 API

```rust
pub fn supported() -> bool;
pub unsafe fn read_info_base() -> u64;
pub unsafe fn write_info_base(base: u64);
pub unsafe fn read_ctrl() -> u64;
pub unsafe fn write_ctrl(v: u64);
pub unsafe fn doorbell(mmio_base: usize, action: u8,
                       target_lpid: u32, payload: u64);
```

## 4. aarch64 SMMUv3

### 4.1 Register block

| offset | name     | content                                  |
|--------|----------|------------------------------------------|
| `0x00` | IDR0     | implementer + caps                       |
| `0x04` | IDR1     | sizes                                    |
| `0x08` | IDR2     | streamID width                           |
| `0x0C` | IDR3     | extra caps                               |
| `0x10` | IDR4     | per-impl                                 |
| `0x14` | IDR5     | granule support / OAS                    |
| `0x20` | CR0      | control 0 (SMMU enable / shareability)   |
| `0x24` | CR0_ACK  | mirror of CR0 reflecting hardware        |
| `0x28` | CR1      | shareability for queue accesses          |
| `0x2C` | CR2      | E2H / RECINVSID / etc.                   |
| `0x44` | GBPA     | global bypass                            |
| `0x80` | STRTAB_BASE | stream-table base                     |
| `0x88` | STRTAB_BASE_CFG | stream-table format                |

`CR0` shape:

| bit | field           |
|-----|-----------------|
| 0   | SMMUEN          |
| 1   | PRIQEN          |
| 2   | EVENTQEN        |
| 3   | CMDQEN          |
| 4   | ATSCHK          |

### 4.2 API

```rust
pub struct SmmuCaps {
    pub s2p:         bool,    // stage-2 supported
    pub s1p:         bool,    // stage-1 supported
    pub ttf16:       bool,    // 16K granule
    pub ttf64:       bool,    // 64K granule
    pub oas:         u8,      // output addr size class
    pub sid_width:   u8,
    pub queue_base_share: u8, // CR1.QUEUE_*SH
}

pub unsafe fn read_caps(reg_base: usize) -> SmmuCaps;
pub unsafe fn read_cr0(reg_base: usize) -> u32;
pub unsafe fn write_cr0(reg_base: usize, v: u32);
pub unsafe fn write_strtab_base(reg_base: usize, paddr: u64, cfg: u64);
```

## 5. Test surface

| smoke                          | asserts                          |
|--------------------------------|----------------------------------|
| `smoke_vtd_caps_decode`        | non-MMIO buffer round-trips      |
| `smoke_amd_vi_caps_decode`     | non-MMIO buffer round-trips      |
| `smoke_rar_supported_path`     | CPUID(7,1).EAX[31] gate          |
| `smoke_smmuv3_caps_decode`     | non-MMIO buffer round-trips      |

The decoders are pure functions of register reads, so the smoke
tests construct a synthetic register block in DRAM and verify
that the bit-positions match the spec layout.

## 6. Out of scope (v0.1)

- Root-table / context-entry / stream-entry table allocation
  + programming.
- Fault-recording pipeline → narf-tracing event format.
- IRQ remapping.
- Atomic-update-batched command-queue submission.
- Per-PCI-segment IOMMU enumeration (lives in `bus/`).
