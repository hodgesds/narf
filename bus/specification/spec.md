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

`read_bar` sizes BARs with Command I/O and Memory Space decoding disabled,
using 16-bit Command accesses so adjacent RW1C Status bits are untouched.
Bus Master and other Command bits are preserved. A 64-bit pair remains
undecoded until both words are restored. High-half/invalid indices are
rejected before mutation; normal errors restore the original Command.
Disable and restoration writes are read back. `BarError::ConfigFailed`
reports a failed configuration transaction; a failed BAR restoration leaves
decoding disabled so no probe address is exposed. The exclusive cfg/BAR
ownership contract requires all BAR users, including IRQ handlers, to be
quiesced for sizing. `map_bar` and `map_bar_control` share this contract.

`map_bar` maps prefetchable MMIO windows with write-combining attributes:
PAT WC on x86_64, MAIR Normal-NC on aarch64. Register BARs remain Device.
These attributes match user mappings of native GPU framebuffer windows.
Unprogrammed windows return `BarError::Unimplemented`; an ioremap failure,
including a conflicting memory type, returns `BarError::MappingFailed`.
`map_bar` never substitutes an unverified physical-address mapping.

`unsafe map_bar_control(device, idx) -> Result<MmioRegion, BarError>` maps
control-register BARs with Device attributes even when PCI marks them
prefetchable. VirtIO register capabilities and every MSI-X table access use
this entry point from their first mapping. Identical ready mappings reuse
their VA; conflicting prior mappings still fail closed. Its exclusive
device/config-space ownership contract is the same as `map_bar`.

`MsixTable::enable()` enables delivery and clears the function mask after
entries and handlers are programmed. `unsafe MsixTable::disable()` masks
the function and clears MSI-X enable; the owner must stop device causes
and synchronize handlers before releasing their state or vector numbers.

`unsafe msi::disable(&MsiConfig)` clears MSI Enable without touching the
programmed message or Multi-Message Enable, so a later `msi::enable`
resumes the same vectors.

`pci_express::clear_and_set_link_control(cap, dev, clear, set) -> u16`
read-modify-writes PCIe Link Control and returns the prior value (Linux
`pcie_capability_clear_and_set_word(PCI_EXP_LNKCTL)`); `LNKCTL_ASPMC` names
the ASPM L0s/L1 field.

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

As implemented, the registry descriptor is
`BusDevice { addr: BusAddr, id: DeviceId, kind: BusKind }` with
`BusKind::{Pcie, VirtioMmio, Platform}`. `Platform(PlatformDevice)`
is the devicetree record (DT enumeration, §3.2 / §5):

- `compatible`: the node's `compatible` list inline, most-specific
  string first, capacity `PLATFORM_COMPATIBLE_CAP` (128) bytes,
  truncated at a string boundary — the strings matching prefers are
  the ones kept. A string's position in the list is the DT match
  specificity measure (§9.2).
- `regs`: up to `PLATFORM_MAX_REGS` (4) decoded `reg` windows,
  translated through ancestor `ranges` at enumeration. Window 0's
  base is the device's `BusAddr::Mmio` key; `DeviceId` is all-zero.
- `irqs`: up to `PLATFORM_MAX_IRQS` (4) interrupts resolved at
  enumeration to architectural INTIDs against the interrupt
  parent's binding. Only the GIC 3-cell form is resolved today;
  a device under another controller keeps `irq_parent` (the
  parent's phandle) but carries no resolved entries.
- `phandle` / `irq_parent`: the node's own phandle and its
  interrupt parent's, for the framework layer. Further phandle
  references (`clocks` / `resets` / `regulators`) are *not* decoded
  at enumeration — their cell widths are properties of the target
  controller, so the framework layer resolves them at probe time,
  re-locating the node by (first compatible string, first `reg`
  base) via `narf_firmware_fdt::for_each_compatible`.

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

Devicetree enumeration (`bus::dt`, aarch64) runs on
`narf_firmware_fdt` — the tree's only FDT walker:

```rust
/// Pure decode of a DTB into device-shaped records: nodes with
/// `status` absent-or-okay, a `compatible`, and a translatable
/// `reg`, excluding the `/cpus` subtree. `reg` windows are
/// translated through ancestor `ranges`; interrupts are resolved
/// to architectural INTIDs against the (inherited) interrupt
/// parent when it carries a GIC binding.
pub fn decode_devices(blob: &[u8]) -> Vec<DtDevice>;
```

`enumerate_dt` (crate-internal, aarch64) turns the decode into
registry devices: `Platform` records as decoded, virtio-mmio
slots probed for a populated device-id (emitted as `VirtioMmio`,
never `Platform`), and the `pci-host-ecam-generic` bridge's ECAM
walked via the shared PCIe enumerator when its window falls in
the low 4 GiB (the legacy guard — a highmem ECAM is described in
the tree but not walked). With no DTB, or a blob that yields
nothing, aarch64 enumeration falls back to the QEMU `virt`
virtio-mmio slot scan.

Appends made after enumeration (hot-plug arrivals, bridge-enumerated
children) are visible to `devices()` immediately. The match-table
dispatcher's binding walk (§9) additionally observes appends made
*during* the walk itself — see §9.5.

Probe-time tree access (DT programme step 5): enumeration retains
the discovered blob, and bindings re-locate their node in it —
matched by the same identity the record carries (first
compatible string + first translated `reg` base) — to decode
node-local data the fixed-size record cannot hold:

```rust
/// The boot DTB retained at enumeration (aarch64); `None` on
/// x86_64 and DTB-less boots.
pub fn dtb_blob() -> Option<&'static [u8]>;

/// Decode the child subtree of the node identified by
/// (`parent_compatible`, `parent_first_reg_base`). Child `reg`
/// values are decoded with the parent node's cells and left
/// untranslated — they live in the parent's local address space
/// (partition offsets, chip-selects). Children ride recursively.
pub fn children_of(
    blob: &[u8],
    parent_compatible: &str,
    parent_first_reg_base: u64,
) -> Vec<DtChild>;

/// Read one property of the identified node itself (a `clocks`
/// phandle list, a `clock-frequency` override).
pub fn node_prop(
    blob: &[u8],
    parent_compatible: &str,
    parent_first_reg_base: u64,
    name: &str,
) -> Option<Vec<u8>>;

/// Resolve a clock phandle to the target node's
/// `clock-frequency` when the target is a fixed-clock style
/// provider. The #1052 clock framework generalises provider
/// resolution; consumers name their fallback explicitly.
pub fn clock_frequency_of_phandle(blob: &[u8], phandle: u32) -> Option<u32>;
```

This is the mechanism the §3.1 framework resolution (clocks /
resets / regulators, and likewise `fixed-partitions` tables and
bus child devices) is specified to use at probe time.

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

### 3.4 Config-space access

```rust
pub const CFG_WINDOW_BYTES: u64 = 4096;

pub fn pci::read_config32(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
    offset: u16,
) -> Result<u32, PciError>;
```

Reads one dword from anywhere in the claimed function's 4 KiB config
window. `pci::save_config` covers the standard type-0 header and
`pci_cap` walks the capability list, but vendors put device-specific
state in 0x40..0x100 that is neither — Intel's HECI firmware-status
words at 0x40 / 0x48 / 0x60 are the motivating case. `offset` must be
dword-aligned and within `CFG_WINDOW_BYTES`, else `PciError::BadOffset`.

A read of a device that has fallen off the bus returns `0xFFFF_FFFF`,
the same as the raw ECAM read; callers that need to distinguish that
from a real all-ones value must check liveness another way.

```rust
pub fn pci::write_config32(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
    offset: u16,
    value: u32,
) -> Result<(), PciError>;
```

Writes one dword with the same offset rules. It exists for state that
`pci::restore_config` does not cover after a device-level reset: PCIe
capability control words and extended capabilities such as Resizable
BAR. Callers write zero into RW1C status halves sharing the dword.

```rust
pub const pci::PM_D3HOT_DELAY_MS: u64 = 10;
pub enum pci::PciPowerState { D0, D1, D2, D3Hot }
pub fn pci::power_state(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice)
    -> Result<Option<PciPowerState>, PciError>;
pub fn pci::set_power_state(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice,
    state: PciPowerState) -> Result<(), PciError>;
pub fn pci::bridge_bus_range(device: &BusDevice) -> Option<(u8, u8)>;
pub fn pci::upstream_bridge(device: &BusDevice) -> Option<BusDevice>;
pub fn pci::sibling_function(device: &BusDevice, function: u8) -> Option<BusDevice>;
```

`power_state` / `set_power_state` read and write the PMCSR PowerState of
the PCI PM capability (`CapNotPresent` without one; `Ok(None)` for an
all-ones read). The write preserves every other PMCSR field, writes 0 to
the RW1C PME_Status bit and refuses D1/D2 the PMC register does not
advertise. Neither waits: the caller sleeps `PM_D3HOT_DELAY_MS` after a
D3hot entry or exit before the next config access, on the timer wheel
(`power/` §3.5 runtime-PM PCI layer). `pm_d3hot_cycle` keeps its own
bounded wait for the SDHCI reset quirk.

`bridge_bus_range` reads a type-1 header's secondary/subordinate bus
numbers. `upstream_bridge` (Linux `pci_upstream_bridge`) finds the
registered bridge whose secondary bus is the function's bus, and
`sibling_function` another function of the same slot; both read only
the type-1 / registry data and need no capability.

### 3.5 Hot-plug

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

As implemented today, hot-plug events flow as `HotplugEvent` via
`hotplug::dispatch_event`; the default dispatcher re-runs
`probe_all` on attach and routes detach to the bound driver's
remove hook (§9.6). The bridge-ISR event sources above remain
Stage-5 work; `dispatch_event` is the seam they will feed.

### 3.6 Loadable-driver PCI bridge

Separately compiled modules cross the bus boundary through C-ABI callbacks
and opaque integers; `BusDevice`, `MmioRegion`, `DmaBuffer`, and their typed
capabilities remain kernel-owned Rust objects.

```rust
pub type ModuleProbeFn = extern "C" fn(dev_token: u64, reserved: u64) -> i32;
pub type ModuleCallbackFn = extern "C" fn(cookie: u64) -> i32;
pub type ModuleTxFn = extern "C" fn(frame: *const u8, len: usize) -> i32;

pub unsafe fn register_module_pci_driver(
    owner: u64,
    name: &str,
    vendor: u16,
    device: u16,
    probe: usize,
) -> i32;

pub fn set_module_probe_call_gate(gate: ModuleProbeCallGate);
pub fn set_module_callback_call_gate(gate: ModuleCallbackCallGate);
pub fn set_module_tx_call_gate(gate: ModuleTxCallGate);
pub fn unregister_module_pci_drivers(owner: u64);

pub fn module_pci_enable(owner: u64, dev: u64, bits: u16) -> i32;
pub fn module_bar_map(owner: u64, dev: u64, bar: u8) -> u64;
pub fn module_mmio_read32(owner: u64, dev: u64, bar: u64, off: u64) -> Option<u32>;
pub fn module_mmio_write32(owner: u64, dev: u64, bar: u64, off: u64, val: u32) -> i32;
pub fn module_mmio_wait32(
    owner: u64,
    dev: u64,
    bar: u64,
    off: u64,
    mask: u32,
    expected: u32,
    timeout_ns: u64,
) -> i32;
pub fn module_dma_alloc(owner: u64, dev: u64, len: usize, domain: DomainId) -> u64;
pub fn module_dma_addr(owner: u64, dev: u64, dma: u64, off: u64) -> Option<u64>;
pub fn module_dma_write(owner: u64, dev: u64, dma: u64, off: u64, src: &[u8]) -> i32;
pub fn module_dma_read(owner: u64, dev: u64, dma: u64, off: u64, dst: &mut [u8]) -> i32;
pub fn module_dma_wait8(
    owner: u64,
    dev: u64,
    dma: u64,
    off: u64,
    mask: u8,
    expected: u8,
    timeout_ns: u64,
) -> i32;
pub fn module_dma_free(owner: u64, dev: u64, dma: u64) -> i32;
pub fn module_msix_enable(owner: u64, dev: u64) -> i32;
pub fn module_msix_claim(owner: u64, dev: u64) -> Result<u16, i32>;
pub fn module_irq_set_handler(
    owner: u64,
    dev: u64,
    vector: u16,
    callback: ModuleCallbackFn,
    cookie: u64,
) -> i32;
pub fn module_spawn_poller(
    owner: u64,
    dev: u64,
    callback: ModuleCallbackFn,
    cookie: u64,
) -> i32;
pub fn module_netif_register(
    owner: u64,
    dev: u64,
    mac: [u8; 6],
    tx_callback: ModuleTxFn,
) -> Result<u32, i32>;
pub fn module_netif_rx(
    owner: u64,
    dev: u64,
    ifindex: u32,
    frame: &mut [u8],
) -> i32;
```

The module subsystem installs all three call gates. They resolve `owner` to the
module's load-time domain and enter that domain before invoking module text.
Datapath contexts retain the per-device capability and reject every operation
whose per-CPU callback owner does not match. Unload runs the module exit hook,
then removes all matches, callbacks, and contexts for `owner` before module
text is unmapped. DMA handles are revocable, bounds checked, and allocated in
the effective load-time domain; the module never receives their CPU mapping.
MSI-X hard handlers remain in FRAME and only claim/account the interrupt; an
in-tree executor task observes `fire_count` and invokes module callbacks
through the domain/lifecycle gate. Poller callbacks use the same task-context
path. Teardown function-masks and disables MSI-X, clears command-register
bits, disables and detaches each handler, calls `synchronize_irq`, frees
vectors, unregisters the module netif, and only then revokes/frees DMA and
device capabilities. MMIO/DMA wait helpers use the scheduler's responsive,
deadline-bounded polling primitive rather than module-local spin loops.
Network TX crosses a permanent in-tree trampoline and the TX call gate; RX is
a synchronous bounded copy into the named interface's stack ingress path.

### 3.7 VMD domains: MEMBAR apertures and MSI remapping

An Intel VMD bridge hides its children behind two apertures — the
bridge's BAR2 (`MEMBAR1`) and BAR4 (`MEMBAR2`) — and intercepts
their interrupts. The bus crate models each bridge as a *VMD
domain* (`vmd_domain`, `vmd_irq`), registered by the VMD driver at
probe time, before the children are installed into the registry:

```rust
pub struct MembarWindow { pub base: u64, pub size: u64, pub reserve_head: u64 }
pub struct VmdDomainInfo {
    pub segment: u16, pub bridge: BusAddr,
    pub membar1: Option<MembarWindow>, pub membar2: Option<MembarWindow>,
    pub msix_entries: u16, pub first_vec: u16,
}
pub fn register_vmd_domain(info: VmdDomainInfo) -> Result<(), VmdDomainError>;
pub fn unregister_vmd_domain(segment: u16) -> Option<VmdDomainInfo>;
pub fn membar_window_of(segment: u16, phys: u64, len: u64) -> Option<u8>;
pub fn allocate_vmd_mmio(segment: u16, size: u64, align: u64) -> Option<u64>;
```

MEMBAR semantics (issue #933 item 3). Programmed child BAR values
are already host addresses — there is no translation on the path —
so the domain's content is containment and allocation:

- `assign_unprogrammed_bars` draws a VMD child's assignments from
  its bridge's aperture (first-fit over unoccupied gaps, MEMBAR1
  before MEMBAR2), never from the host MMIO pool, and treats a BAR
  holding an address outside the aperture as unprogrammed.
- `map_bar` / `map_bar_control` refuse a VMD child's BAR that does
  not decode inside the aperture.
- MEMBAR2's head (`0x2000`, or `0x2010` on MEMBAR-shadow parts) is
  reserved for the bridge's own MSI-X table and is never allocated
  to a child. Programmed BARs are noted as occupied when observed
  (assignment and mapping both note), so allocations route around
  ranges firmware or an earlier probe already claimed.

MSI remapping (issue #933 item 4). The VMD driver programs the
bridge's own MSI-X table with one host vector per entry, clears
VMCONFIG's `MSI_RMP_DIS` bit, and registers the entries with
`vmd_irq::register_bridge_domain`, which installs a demux handler
on each bridge vector. Child drivers see no API change:
`MsixTable::program_vector` and `program_msi` check whether the
device lives on a registered VMD segment and, if so, substitute
the remap message — the standard MSI address base carrying the
*bridge entry index* in the destination field, data zero (the
Linux `vmd_compose_msi_msg` shape) — and record the
(child vector → bridge entry) mapping. Entry policy follows Linux
`vmd_next_irq`: NVMe-class children (`class >> 8 == 0x0108`) get
the least-loaded entry at or above `first_vec + 1`; all other
classes share the `first_vec` entry (`1` on client parts, where
entry 0 stays free; `0` elsewhere). When a bridge vector fires,
the demux re-dispatches each recorded child vector through
`interrupts::dispatch::on_irq`; an entry with no children reports
spurious. Legacy MSI collapses onto one entry, as the remap
ignores message data — MSI's only per-vector signal.

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
- PCIe: ECAM base from the devicetree `pci-host-ecam-generic`
  node's `reg` property (low-4-GiB windows only today) or ACPI
  MCFG on SystemReady platforms.
- MSI via GICv3 ITS; `msi-parent` devicetree node points to the ITS.
- Platform devices enumerated from the whole devicetree (minus
  `/cpus`) in one `narf_firmware_fdt` walk: `compatible` strings
  keyed against the DT match table (§9), `reg` windows decoded
  through parent `ranges`, interrupts resolved through the
  inherited interrupt parent to GIC INTIDs at enumeration time.

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

As implemented, the dispatcher carries two tables in
`driver_match` — `PciMatch` (PCIe kinds above) and `DtMatch`
(`{ name, compatible, probe }`) — feeding one shared walk:
candidate selection is per-kind, everything after it (cap mint,
§9.3 outcomes, §9.5 appended-device handling, §9.6 binding
records + remove hooks keyed by match name) is common. A
`DtMatch` probe receives the `BusKind::Platform` device with the
same `Cap<BusDeviceCap, Write>` mint as a PCI probe.
Virtio-MMIO devices have no table entries; they keep their own
discovery shape.

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

For devicetree matches, specificity is a property of the
*device*: the matched string's position in the device's
`compatible` list (position 0, the most-specific string, wins),
with registration order as the tie-break — rules 2–3 above do
not apply across the DT table today.

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

### 9.5 Devices appended during the walk

A probe may append devices to the registry while `probe_all` is
walking it — bridge drivers do this: the Intel VMD probe
enumerates the functions behind the bridge and appends them
under a synthetic segment (issue #933). The walk therefore
iterates by index over a refreshable snapshot: when the walk
catches up with the snapshot it re-reads the registry and
continues over the appended tail, so devices appended by an
earlier probe in the same call are attempted, in registry
order, exactly once each, before the call returns.

The registry is append-only during a walk — probes append
through `append_devices`; `install` remains an enumeration /
test-setup operation — so the already-walked prefix never
reorders and no device is attempted twice by one call. This
preserves the staged-initcall boot ordering (a bridge
registered at `Stage::Device` has its children bound by the
same walk that binds the bridge) and the hot-plug dispatcher's
semantics (§3.5): an Attach that appends a bridge sees the
bridge's children bound by the same re-run, not by a later
event.

### 9.6 Detach / remove hooks

`probe_all` records every binding it commits — the device plus
the name of the match that claimed it, including bindings for
devices appended during the walk (§9.5), which are recorded by
the same commit path and are detachable the same way. A driver
whose devices need real teardown registers a remove hook per
match name (`register_remove(name, PciRemoveFn)`, a companion
registry: `PciMatch` itself carries no remove field, so the ~90
in-tree match literals are untouched). `detach(authority, addr)`
drops the binding record and, when the bound match name has a
hook, invokes it with the bound device and a freshly minted
`Cap<BusDeviceCap, Write>` (the same mint as probing). Detach is
cap-gated on the registry authority and reports whether a
binding existed; a hookless driver is simply unbound.

The default hot-plug dispatcher's `Detach` arm routes here:
`HotplugEvent::Detach { addr }` → `detach` under the bootstrap
registry authority. Ordering invariant for future enumeration
work: a device must be detached *before* its record leaves the
registry — `detach` mints the hook's cap through the registry,
so a device removed first would silently skip its teardown.

### 9.7 VMD remap cleanup on detach

`detach` also releases the device's VMD remap mappings
(`vmd_irq::release_device`, §3.7) whenever a binding is dropped:
a detached child's vectors must never be dispatched to again, and
the bridge entries' load accounting must not keep counting a gone
device. The release runs before the remove hook, so a hook that
re-programs the device cannot resurrect a stale mapping. Detaching
the *bridge* (its own remove hook) unregisters the whole domain —
resource windows and IRQ domain together; child bindings are
unaffected, but their remap mappings are dead from that point and
are dropped with the IRQ domain.

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
