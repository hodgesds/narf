# bus — Design Notes
_2026-04-22_

## Load-bearing decisions

**`discover_all()` returns a `&'static [DeviceInfo]` — a boot-time snapshot.**
This means hot-plug arrivals after boot are not in the static array; callers
must use `watch()` for dynamic devices. The API is correct but the split creates
a discoverability problem: code that calls `discover_all()` once will silently
miss hot-plugged devices. There is no `devices()` function that includes both
static and dynamic devices under a unified view. The `devices()` iterator in §3
is listed alongside `discover_all()` without clarifying whether it is equivalent
to `discover_all()` or a superset that includes later arrivals.

**Exactly one driver holds `Cap<BusDevice, _>` per device.** This is the correct
exclusivity model, but the spec says "the framework enforces" without specifying
*when* and *how* enforcement happens. In a hot-plug scenario: driver A holds
`Cap<BusDevice>` for slot X; device X is removed then re-inserted; a new device
now occupies slot X. Can driver A's cap be re-used for the new device, or is it
revoked and a fresh claim required? The iommu summary is clear that
"per-device translation tables" mean each device needs its own IOMMU context.
Hot-plug must revoke the old `Cap<BusDevice>` and mint a new one with a new
IOMMU context. The spec does not state this.

**ACPI AML interpretation is deferred but the boundary is fuzzy.** §8 says
"table-only on x86_64, devicetree on aarch64, defer AML." But ACPI SRAT (for
NUMA topology) and HPET (high-precision timer) are real tables that `bus/` or
`memory/` need. AML is only required for `_CRS` / `_PRS` resource routing and
`_INI` device initialization. The spec should split "no AML execution" (firm
commitment) from "no ACPI tables beyond MADT/MCFG" (which is overly
restrictive). SRAT parsing is table-only and needed for NUMA-aware allocation.

**The `claim` API requires a `Cap<BusRegistry, Claim>` but no spec says where
the BusRegistry cap comes from.** At boot, `bus/` creates the registry.
Something must hold the root `Cap<BusRegistry, Claim>` — presumably a driver
manager in `drivers/`. But `drivers/` is Stage 2 and `bus/` Stage 2 as well.
The bootstrap sequence (who holds the initial BusRegistry cap and how it
distributes Claim rights to drivers) is unspecified.

## Divergences from precedent

**vs. Linux:** Linux's `struct device` is a universal base type extended by
bus-specific types (`pci_dev`, `platform_device`). Every device carries a
`dev_pm_info`, `dev_iommu`, `coherent_dma_mask`, etc. — a 400-byte blob even
for a trivial device. NARF's `DeviceInfo` is much leaner, which is correct for
a capability-gated system. But Linux's design embeds the IOMMU group in `struct
device` because it is discovered at enumeration time. NARF's `DeviceInfo` has
`iommu: Option<IommuGroup>` which is correct, but `IommuGroup` is just an opaque
ID — the actual IOMMU context is in `io/`. The iommu summary warns that
IOMMU-group membership is a quirky, per-vendor affair: "Linux has a long list of
per-vendor quirks." NARF should inherit Linux's IOMMU ACS quirk table rather
than re-deriving it, at least for Stage 2.

**vs. Fuchsia:** Fuchsia's driver framework uses "device protocols" that are
capability-like handles. A driver binds to a device by receiving a channel to
the device protocol. NARF's `Cap<BusDevice, _>` is semantically equivalent.
The difference is that Fuchsia's device protocol is versioned and can evolve;
NARF's cap is an opaque token. NARF should borrow Fuchsia's versioned-protocol
concept for driver-to-device communication — a driver manifest should declare
which version of a device protocol it implements.

**PCIe ECAM isolation:** The pci-config-space summary recommends PKS/MTE
enforcement on ECAM regions — "each device's config space becomes an isolatable
page." NARF should assign each device's 4 KiB ECAM window to the device's
owning domain (DOMAIN_BUS during enumeration, then transferred to the driver's
domain on claim). The spec says "the driver's manifest names the device by
DeviceId" but doesn't say the driver gets a direct-mapped config-space page —
it only says the claim bundles "a config-space window." Whether that window is
mapped into the driver's domain directly or mediated through `bus/` is
unresolved. Direct mapping is necessary for PCIe capability register manipulation
(MSI-X BAR, power state transitions) that must be fast.

**Hot-plug NAK floods:** The pcie-architecture summary notes that hot-unplug
mid-DMA generates "NAK floods." Linux handles this with a device-error recovery
path in the AER (Advanced Error Reporting) driver. NARF's spec mentions
"hot-plug removal waits for the owning driver's quiesce before actually
unmapping" but has no error path for when the driver *doesn't* quiesce (e.g.,
driver is stuck in an infinite loop or the domain is faulted).

## Proposed spec changes

- §3.2 Enumeration API: **Merge `discover_all()` and `devices()` into a single
  `devices() -> impl Iterator<Item = &'static DeviceInfo>`** that covers all
  present devices at call time (both boot-time and hot-plugged arrivals). Add
  `snapshot() -> &'static [DeviceInfo]` as the boot-time-only view explicitly
  named for its semantics. Current naming implies `discover_all()` is complete
  but it misses hot-plug devices.

- §3.3 Device capability: Add **"`Cap<BusDevice, _>` carries a generation stamp
  matching the device's enumeration epoch. Driver framework must verify the stamp
  on every use; a removed-and-reinserted device has a new generation."** This
  closes the hot-plug revocation gap and uses epoch semantics consistent with
  `capabilities/` design.

- §3.4 Hot-plug: Add **a `quiesce_timeout` to the removal path**: "Hot-plug
  removal sends a `Removed` event; the framework has 500 ms to quiesce the
  driver. After timeout, the domain is forcibly deactivated and the
  `Cap<BusDevice>` is revoked, even if the driver has not acknowledged." Define
  what "forcibly deactivated" means: the domain's PKS rights are cleared by the
  Frame, preventing further MMIO access to BARs.

- §4 Invariants: Add **"The ECAM window for each PCIe function is mapped in
  DOMAIN_BUS during enumeration. On `claim()`, it is remapped into the claiming
  driver's domain. The driver holds the only writable mapping."** Without this,
  two drivers could simultaneously read/write the same function's config space.

- §5 Architecture notes (x86_64): **Add ACS (Access Control Services) check
  during enumeration.** If ACS is absent on a PCIe bridge, peer-to-peer DMA
  between devices behind that bridge bypasses the IOMMU. NARF must detect
  ACS-absent bridges and refuse P2P DMA capability grants for devices behind
  them, or deny the claim entirely. The iommu summary confirms this is a real
  isolation hazard.

- §8 Open questions — ACPI interpreter: **Resolve immediately: NARF will not
  execute AML.** Replace with: "NARF parses ACPI tables MADT, MCFG, SRAT, FADT,
  and HPET without AML execution. All hardware enumeration uses these tables plus
  devicetree. DSDT parsing for `_CRS` resource routing is deferred to post-1.0
  with an explicit compatibility note."

## Open invariants / cross-subsystem hazards

**bus ↔ io:** §4 says "IOMMU group membership is consistent — removing one
device from a group without quiescing its peers is disallowed." But `io/` owns
the IOMMU context, not `bus/`. When `bus/` removes a device, it must coordinate
with `io/` to tear down the IOMMU mapping. If `io/` is not yet initialized (Stage
2 vs. Stage 3 boundary), `bus/` must defer removal or refuse to claim devices
that need IOMMU isolation. This ordering constraint is not in either spec.

**bus ↔ interrupts:** MSI-X vector allocation is listed as `interrupts/`-owned,
with `bus/` only "requesting" vectors. But MSI-X table setup requires writing
to the device's MSI-X BAR (a config-space write followed by a BAR write). Who
performs the BAR write? If `interrupts/` allocates the vector but doesn't know
the device's domain, and `bus/` knows the device's domain but hasn't allocated
the vector, neither subsystem can write the MSI address register. Specify that
`bus/` performs the BAR write after receiving the vector address from
`interrupts/`, while holding the device's config-space cap.

**bus ↔ memory:** NUMA topology (ACPI SRAT / DT `numa-node-id`) affects memory
allocation decisions. `memory/` needs NUMA node information. §8 asks "who owns
NUMA parsing — `bus/` or `memory/`?" The answer should be **`bus/`** — NUMA
topology is derived from ACPI/DT, which is `bus/` territory. `bus/` parses SRAT
and exposes `DeviceLocation::numa`. `memory/` reads `numa` from `DeviceInfo`
during physical allocator initialization. But `memory/` initializes before `bus/`
finishes enumeration. This chicken-and-egg problem requires `memory/` to use a
NUMA topology from a pre-`bus/` source (early ACPI table parse in `boot/`).

**bus ↔ capabilities:** The root `Cap<BusRegistry, Claim>` must be minted
somewhere. During `frame::init_bsp`, `capabilities::bootstrap` is called.
`bus/` must register with `capabilities/` to get a `BusRegistry` object and
the associated root cap. This implies `bus::init()` is called from
`frame::init_bsp` after `capabilities::bootstrap`, but the stage-1/2 boundary
means `bus/` doesn't exist until Stage 2. The bootstrap call sequence must
reserve a slot for `BusRegistry` in the Stage 1 cap bootstrap, even if the
actual registry is populated in Stage 2.

## Additional opinionated commentary

The bus spec is well-scoped but the `claim()` API has a bootstrap problem that
will surface immediately in Stage 2. The `Cap<BusRegistry, Claim>` required for
`claim()` creates a who-watches-the-watchmen problem: the entity that holds the
root BusRegistry cap controls which drivers can claim which devices, which is
effectively the system's device policy. In Linux this is `udev`; in Fuchsia it
is the component manager; in NARF it is... not specified. The spec defers this
to "the driver framework," but the driver framework is also Stage 2 and is
not a NARF subsystem with its own spec. This needs to be addressed, not deferred.

The ACPI AML question is correctly answered as "not now" but the spec should
be more specific about what ACPI tables ARE parsed. A kernel that cannot parse
SRAT cannot do NUMA-aware allocation; one that cannot parse MADT cannot set up
the LAPIC. These are not AML — they are static binary tables. The spec conflates
"no AML" with "minimal ACPI" in a way that may be read as "no ACPI at all,"
which would break x86_64 server support immediately.
