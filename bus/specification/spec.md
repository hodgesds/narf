# bus — Specification

> Status: **v1.0** (Stage 3 design lock). v0.1 covered
> enumeration + claim; v1.0 locks the `Cap<BusDevice, _>` mint
> protocol the drivers framework relies on, the match-table
> dispatcher contract, the hot-plug event API, per-driver IOMMU
> group binding, and ABI versioning.

## 1. Purpose & scope

**Owns:**

- PCIe enumeration via ECAM — bus/device/function walk, header
  parsing, BAR sizing, capability list discovery (MSI/MSI-X, PM,
  Express, ATS, PRI, ACS).
- MMIO / platform-bus enumeration from ACPI tables (MCFG, DSDT
  device nodes) or devicetree (`/soc`, `/pci` nodes).
- **Device registry** — a cap-addressed list of discovered devices.
- MSI / MSI-X vector allocation and binding via `interrupts/`.
- IOMMU group discovery (coordinating with `io/`).
- Hot-plug events (PCIe Native Hot Plug + firmware notifications).
- Runtime device injection (virtio-mmio device tree patching for VMs).

**Does NOT own:**

- Driver matching / binding policy — `drivers/` framework does that
  using a manifest lookup against bus output.
- DMA buffer allocation — `io/`.
- IRQ routing — `interrupts/` (we only allocate vectors).
- Per-driver config-space reads beyond the header — each driver owns
  its own config-space cap, just gated here.

## 2. Assumptions

- `arch/` provides MMIO access primitives.
- `memory/` can map config-space (or present it pre-mapped from boot).
- `boot/` has already handed us ACPI RSDP / devicetree pointers.
- `interrupts/` has a MSI-vector allocator we can request from.
- `capabilities/` can mint `Cap<BusDevice, _>` tokens.

## 3. Public interface

### 3.1 Device descriptor

```rust
pub struct DeviceId { pub vendor: u16, pub device: u16, pub class: u32 }

pub struct DeviceLocation {
    pub bus:      BusKind,            // Pcie { seg, bus, dev, fn_ } | Mmio { base } | Devicetree(path)
    pub numa:     Option<NumaNodeId>,
}

pub struct DeviceInfo {
    pub id:       DeviceId,
    pub loc:      DeviceLocation,
    pub bars:     [Option<Bar>; 6],   // PCIe; MMIO case uses bars[0]
    pub msi:      MsiSupport,
    pub iommu:    Option<IommuGroup>,
}
```

### 3.2 Enumeration API

```rust
/// All devices present at this moment — both boot-time and
/// hot-plugged. Iterated lazily; safe to walk while hot-plug events
/// are firing because the registry uses RCU.
pub fn devices() -> impl Iterator<Item = &'static DeviceInfo>;

/// Boot-time-only snapshot, named for its semantics. Returns the set
/// of devices present at the end of `bus::init`. Stable for the
/// kernel's lifetime; never reflects hot-plug. Useful for the
/// boot-log "we found these devices" report and for tests.
pub fn snapshot() -> &'static [DeviceInfo];

pub fn watch() -> impl Stream<Item = BusEvent>;       // hot-plug arrivals / removals

#[cfg(target_arch = "aarch64")]
pub unsafe fn discover_pmu_ppi(dtb: PhysAddr) -> Option<u32>;
```

`discover_pmu_ppi` accepts only an `arm,armv8-pmuv3` node with a GIC
three-cell PPI interrupt specifier and returns its architectural INTID. It has
no platform-default fallback because the PMU interrupt is implementation-defined.

### 3.3 Device capability

```rust
pub fn claim(info: &DeviceInfo, cap: &Cap<BusRegistry, Claim>) -> Cap<BusDevice, _>;
```

`Cap<BusDevice, _>` bundles:

- Permission to map BARs via `memory/`.
- Permission to request MSI/MSI-X vectors via `interrupts/`.
- Permission to create DMA contexts via `io/`.
- A config-space window for the device (PCIe extended config for
  PCIe devices).

A driver normally gets one such cap per device it owns; the
driver's manifest names the device by `DeviceId` and the
framework matches.

### 3.4 Hot-plug

```rust
pub enum BusEvent {
    Arrived(DeviceInfo),
    Removed(DeviceLocation),
    LinkChange(DeviceLocation, LinkState),
}
```

Hot-plug paths:
- **PCIe Native Hot Plug** (slot status interrupts on downstream
  bridges) — subscribe and emit `Arrived` / `Removed`.
- **Firmware-mediated** (ACPI `Notify(0)` / `Notify(1)`) — translate
  into the same events.
- **virtio-mmio / platform-bus injection** — handled the same way
  for virtio transports presented after boot.

## 4. Invariants & safety properties

- The device registry is read-mostly and uses RCU for lookups.
- At most one driver holds `Cap<BusDevice, _>` per device (the
  framework enforces).
- BAR maps honour caching type (prefetchable vs. not).
- IOMMU group membership is consistent — removing one device from a
  group without quiescing its peers is disallowed.
- Hot-plug removal waits for the owning driver's quiesce before
  actually unmapping. **Quiesce timeout is 500 ms (configurable).**
  After timeout, `bus/` forcibly deactivates the domain — the Frame
  clears the domain's PKS rights so subsequent BAR access faults —
  and revokes the `Cap<BusDevice, _>` regardless of driver
  acknowledgement. This bounds the worst case for an unresponsive
  driver; cleaner driver code never hits the timeout.
- **ECAM window is mapped exclusively into the claiming driver's
  domain.** During enumeration each function's ECAM window lives in
  `DOMAIN_BUS`; on `claim()`, the framework remaps it into the
  driver's domain with the bus-side mapping torn down. Two drivers
  cannot simultaneously read/write the same function's config space.
  This is the only sound way to expose config-space writes (MSI-X
  enable, capability programming) to a driver while keeping `bus/`
  out of the per-config-write path.
- **Every use of `Cap<BusDevice, _>` goes through `Cap::invoke`**
  (see `capabilities/` §3–§4). A hot-removed device has its object
  epoch bumped; any cached `Cap<BusDevice, _>` in a driver returns
  `Err(Revoked)` on next use. Drivers must not reach around the
  capability to the underlying device pointer.

## 5. Architecture notes

### x86_64
- PCIe: ECAM base from ACPI MCFG, 4 KiB per function.
- Legacy config access (`0xCF8` / `0xCFC`) only for *very* old CPUs
  — NARF doesn't support these.
- MSI / MSI-X vector allocation via LAPIC vector space coordinated
  with `interrupts/` (UIPI receivers where the driver is UIPI-enabled).
- **ACS check during enumeration.** PCIe Access Control Services
  must be present on every bridge in a path before P2P DMA is
  allowed across that path. `bus/` walks the bridge chain on each
  device and records an `acs_clean: bool` in `DeviceInfo`.
  Devices behind ACS-absent bridges are denied `Cap<BusDevice, P2pDma>`
  outright — without ACS, peer-to-peer DMA bypasses the IOMMU and
  the isolation claim is void.

### aarch64
- PCIe: ECAM base from devicetree `reg` property or ACPI MCFG on
  SystemReady platforms.
- MSI via GICv3 ITS; `msi-parent` devicetree node points to the ITS.
- Platform-bus devices enumerated from devicetree's `/soc` subtree,
  with `compatible` strings keyed against the driver registry.

## 6. Dependencies

- **Consumes:** `memory/` (config-space maps, BAR maps), `arch/`
  (MMIO access), `boot/` (ACPI/DT pointers), `interrupts/`
  (MSI-vector allocation), `io/` (IOMMU group bootstrap),
  `capabilities/`, `rcu/` (registry reads), `tracing/` (hot-plug
  events).
- **Provides to:** `drivers/` framework (device discovery + claim
  flow).

## 7. Stage assignment

| Stage | Lands                                                             |
| ----- | ----------------------------------------------------------------- |
| 2     | Boot-time PCIe ECAM walk; MMIO discovery from ACPI/DT; device registry with claim API. |
| 3     | MSI-X allocation path; PCIe Native Hot Plug; IOMMU-group coordination with `io/`. |
| 4     | Thunderbolt / PCIe switch awareness; ACPI notify integration; virtio-mmio runtime injection for VMs. |

## 6a. CXL Component Register Block + CCI mailbox

`cxl/` is a clean-room codec for the CXL Component Register Block
mailbox plus the Component Command Interface (CCI). References
(public-only):

- **Compute Express Link (CXL) Specification, Revision 3.1** — CXL
  Consortium. Public document. §8.2.8 (Component Register Block:
  RCRB / DVSEC for CXL 1.1+ devices, Memory-Mapped Component
  Registers). §8.2.9.1 (Mailbox Capabilities + Control + Status
  + Background Command Status registers, with Payload Size encoded
  as a log2 byte count). §8.2.9.2 (Mailbox Command Format —
  opcode | input length | command payload | return code | output
  length | output payload). §8.2.9.5 Component Command Set table
  8-44 (Identify, Background Operation Status, Get FW Info,
  Get Timestamp / Set Timestamp, Health Info, Get Supported Logs,
  Get Log).

Surfaced:
- `pack_command_register` / `unpack_command_register` for the
  64-bit Command register (low 16 = opcode, bits 36..16 = 21-bit
  input payload length).
- `pack_status_register` / `unpack_status_register` for the
  Background flag + return code + vendor-extended-status fields.
- `BackgroundStatus` for the Background Command Status register
  (percentage 0..100, complete bit, return code, vendor extended).
- `IdentifyResponse::parse` covering FW revision / max msg size /
  component type / VID/DID/SubsysVID/SubsysDID / 64-bit serial.
- `get_log_input` builder (UUID + 4-byte offset + 4-byte length).
- `HealthInfo::parse` covering Health/Media status bytes,
  life-used %, device temperature, dirty-shutdown count, and
  corrected volatile / persistent error counts.
- DVSEC vendor 0x1E98 + Component Register Locator DVSEC ID 0x0008
  surfaced as constants.

## 7a. PCIe DOE (Data Object Exchange)

`pci_doe/` is a clean-room codec for the PCIe DOE Extended
Capability. References (public-only):

- **PCI Express Base Specification, Revision 6.0** — PCI-SIG.
  §6.30 Data Object Exchange (DOE) Extended Capability: cap-id
  0x002E, register layout (DOE Capabilities / Control / Status /
  Write Mailbox / Read Mailbox), 2-DWORD object header (Vendor ID
  in DWORD 0 low 16 bits, Data Object Type in DWORD 0 bits 23..16,
  Length in DWORD 1 bits 17..0 with the special-case 0 = 2^18).
- **PCI Express Base Specification, Revision 5.0** — first ratified
  DOE; layout matches the 6.0 wording.
- **DMTF DSP0274 SPDM** — defines the SPDM-over-DOE wrapper.
- **PCI-SIG public Vendor ID list** — 0x0001 (PCI-SIG) is the
  vendor used for the DOE Discovery protocol.

The codec is bus-agnostic — it produces / consumes the DWORD stream
the host writes to the Write Mailbox and reads from the Read Mailbox.
The MMIO bring-up and Status-bit polling live in the consumer driver
(SPDM, CXL IDE).

## 7b. PCIe IDE (Integrity & Data Encryption)

`pci_ide/` is a clean-room codec for the IDE Extended Capability
plus the IDE_KM key-management protocol. References (public-only):

- **PCI Express Base Specification, Revision 6.0** — PCI-SIG.
  §6.33 Integrity & Data Encryption (IDE) Extended Capability:
  cap-id 0x0030, capability + control + per-stream register
  blocks (Stream Capabilities / Control / Status — Stream Enable,
  Aggregation, PCRC, Algorithm = AES-GCM-256 / AES-GMAC-256,
  Selected, TC, Stream ID), per-RID association blocks for
  Selective Streams. §6.33.4 IDE_KM message format carried over
  DOE (vendor 0x0001, type 0x07): KEY_PROG / KP_ACK / K_SET_GO /
  K_SET_STOP / K_GOSTOP_ACK / KEY_QUERY / K_QUERY_RESP, plus the
  Stream Selector word (Stream ID + Sub-Stream PR/NPR + Key Set
  A/B + Direction Rx/Tx).

The codec is bus-agnostic — it produces the bytes the host writes
into a DOE message body. The MMIO Stream-register read/write
plumbing is the consumer driver's responsibility.

## 8. Open questions

- ~~**ACPI interpreter**~~ **Resolved (v0.2): NARF will not execute
  AML.** Hardware enumeration uses ACPI tables MADT, MCFG, SRAT,
  FADT, and HPET (parsed without AML execution) plus devicetree on
  aarch64. DSDT parsing for `_CRS` resource routing is deferred to
  post-1.0 with an explicit compatibility note in `arch/` open
  questions. Platforms that require AML for basic device discovery
  (some pre-2018 desktop boards, certain embedded ACPI-on-aarch64
  systems) are unsupported in Stage 1–4.

## 9. Match-table dispatcher

The dispatcher is the single point that binds a `BusDevice` to
a driver. Static-linked and dynamically-loaded drivers feed
into the same table.

### 9.1 Match entry types

```rust
pub enum MatchEntry {
    Pcie       { vendor: u16, device: u16, class: Option<u32> },
    VirtioMmio { device_id: u32 },
    AcpiHid    { hid: &'static str },
    DtCompat   { compat: &'static str },
    Catchall,                       // explicit "I'll match anything"
}
```

### 9.2 Specificity ordering

When multiple registrations could match a given device:

1. **Specificity**: `(vendor, device, class)` > `(vendor,
   device)` > `(vendor)` > `Catchall`. Class-only matches
   slot between vendor+device and vendor-only.
2. **Driver version** (newer wins) — supports live upgrade
   per `drivers/spec` §17.7.
3. **SDK minor** (newer wins) — when two driver versions are
   tied, prefer the build against a newer SDK.
4. **Registration order** (earlier wins) — final
   deterministic tie-break.

The dispatcher maintains the table in specificity order; lookup
is linear in the number of entries matching the device's bus
type. With hundreds of drivers this is still microseconds; the
table can be promoted to a hash on (vendor, device) if it
becomes hot.

### 9.3 Probe outcomes

After mint + `Driver::probe(env)`:

- `Ok(())`: binding committed; device removed from candidate
  list. Match dispatcher records `instance_id`.
- `Err(NotForMe)`: this driver declines (e.g. virtio-blk
  driver inspecting the device's `device_id` register and
  finding it's not actually blk despite the PCI ID match).
  Caps minted for probing are revoked; device returns to
  candidate list, next-most-specific match attempted.
- `Err(other)`: driver bound but failed init. Device is left
  in `FailedBind` state; tracing event emitted; no further
  match attempts (would-be infinite-loop on broken devices).

### 9.4 Hot-plug retroactive matching

When a driver registers (statically at boot or dynamically at
load), the dispatcher walks the existing device registry and
attempts probing for any device that previously had no match.
This is what lets a module load late and pick up its devices.

## 10. `Cap<BusDevice, _>` mint protocol

Resource bundle minted at probe binding (`drivers/spec` §7.2
step 6), every cap badged with the bound `instance_id`:

| Cap                        | Rights granted | Purpose                       |
| -------------------------- | -------------- | ----------------------------- |
| `Cap<BusDevice, Read>`     | config-space read, BAR map | Driver discovers device      |
| `Cap<BusDevice, Write>`    | + config-space write       | Capability programming, MSI-X enable |
| `Cap<BusDevice, Dma>`      | + DMA bus mastering        | Allocate `Cap<DmaBuffer,_>`  |
| `Cap<BusDevice, P2pDma>`   | + P2P DMA across bridges   | Only granted if ACS clean     |
| `Cap<MsiXTable, Write>`    | program MSI-X table        | Required for `enable_msix`    |
| `Cap<IrqVector, Read>`     | call `wait_for_irq`        | Per-vector after `enable_msix` allocates |
| `Cap<IommuContext, Read>`  | per-driver IOMMU domain    | Bound by `io/` for DMA        |

Rights are additive (each subsumes the prior). A driver that
only needs read access to config space (a passive enumerator)
gets `Cap<BusDevice, Read>` and can derive nothing further.

The cap bundle is **non-transferable** between driver
instances (`capabilities/spec` §8) — instance A cannot pass
its `Cap<BusDevice, _>` to instance B even within the same
driver crate.

## 11. Resolved decisions

### 11.1 Config-space access policy (resolved)

**Decision (was open):** the driver gets a direct-mapped cap
to **its own** config space (the 4 KiB ECAM page); read/write
go through MMIO accessors that route through the cap's badge
check (`Cap<BusDevice, Write>` → can write).

Two security-sensitive fields are **redirected through `bus/`**
even with `Write` rights:

- **ACS bits** (Access Control Services) — flipping ACS could
  enable peer-to-peer DMA bypassing the IOMMU. Only `bus/` may
  modify; drivers that need ACS reconfiguration request it via
  `Cap<BusDevice, BusReconfigureAcs>` (a privileged cap held
  only by the bus admin process).
- **ATS enable bit** — modified only via the `enable_ats` op
  in `io/spec` §9.1, which validates IOMMU readiness.

Other config-space writes (vendor-specific registers,
device-specific capabilities) are direct: drivers know best
how to drive their own devices.

### 11.2 NUMA discovery ownership (resolved)

**Decision (was open):** **`bus/` parses NUMA**, not `memory/`.
ACPI SRAT and DT `numa-node-id` are device-topology tables; they
fit naturally with the rest of bus enumeration. `memory/`
consumes the parsed `NumaNodeId` per page-frame allocation but
doesn't own the source-of-truth.

`bus/` exports `cpu_node(cpu_id)` and the per-`BusDevice`
`numa: Option<NumaNodeId>` field. `memory/` and `io/` consume
both. `scheduler/` consumes `cpu_node` for stealing locality.

### 11.3 Legacy PCI / legacy IRQ (resolved)

**Decision (was open):** **deferred to a separate
`drivers/legacy-pci` crate at Stage 5+**. Stage 1–4 supports
PCIe-only and PCIe-presented-as-PCI (QEMU q35, modern hardware
with legacy compatibility modes). True legacy PCI (no ECAM,
8259 PIC, IDE/UHCI controllers) is not in the critical path
for hundreds-of-drivers scaling; it's a niche per-platform
thing.

The legacy support, when it lands, is a separate driver crate
that registers its own match table for vendor IDs known only
in legacy form. The framework doesn't need awareness; the
crate does its own probing and capability minting using the
same cap kinds.

## 12. ABI versioning

`bus/` exports tagged at `@v0`:

- `MatchEntry` enum layout — frozen at v1.0.
- `BusDevice` struct field set — additions are minor bumps.
- `BusEvent` variants for hot-plug — adding variants is a
  minor bump (callers must use exhaustive match with a
  fall-through `_ => {}` arm; the SDK's exported enum is
  `#[non_exhaustive]`).
- Cap badge layout — part of cap-ABI, follows
  `CAP_ABI_MAJOR`.

Currently `BUS_ABI_MAJOR = 1`, `BUS_ABI_MINOR = 0`.

## 13. Open questions

(none — all v0.1 questions resolved in §11)
