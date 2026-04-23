# bus — Specification

> Status: **Outline v0.1** (Stage 2 → 3).

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
```

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

## 8. Open questions

- ~~**ACPI interpreter**~~ **Resolved (v0.2): NARF will not execute
  AML.** Hardware enumeration uses ACPI tables MADT, MCFG, SRAT,
  FADT, and HPET (parsed without AML execution) plus devicetree on
  aarch64. DSDT parsing for `_CRS` resource routing is deferred to
  post-1.0 with an explicit compatibility note in `arch/` open
  questions. Platforms that require AML for basic device discovery
  (some pre-2018 desktop boards, certain embedded ACPI-on-aarch64
  systems) are unsupported in Stage 1–4.
- **Config-space access from drivers.** A driver legitimately needs
  to read/write its own config space (MSI-X capability, PCIe
  capability registers). Mediate through `bus/`, or hand the driver
  a direct-mapped cap? Leaning: mediate for writes to
  security-sensitive fields (ACS, ATS), direct for others.
- **NUMA discovery.** Driven from ACPI SRAT / `numa-node-id` in DT.
  Who owns the parsing — `bus/` or `memory/`?
- **Legacy PCI (pre-PCIe) and legacy IRQ.** Support needed for some
  embedded targets; deferred to Stage 4.
