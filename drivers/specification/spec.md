# drivers (framework) — Specification

> Status: **Outline v0.1** (Stage 2).

## 1. Purpose & scope

**Owns:** The contract every driver implements, the driver manifest
format (what caps / MMIO regions / IRQs a driver needs), lifecycle
(load, start, quiesce, teardown), failure containment policy.

**Does NOT own:** Bus enumeration specifics (PCIe, MMIO, devicetree —
those become separate sub-specs later), per-driver logic.

## 2. Assumptions

- `memory/` can allocate a driver a dedicated PKS/MTE domain. **The
  system has at least `N_drivers + 4` free PKS/MTE domain slots,
  where `N_drivers` is the number of concurrently loaded drivers
  with dedicated domains.** With six driver slots in
  `security-model/` §4.1's namespace, this caps the dedicated-domain
  driver set at six until `memory/`'s multiplexing decision lands;
  exhaustion is a hard `Err(NoDomain)` on driver load, not a
  silent share-fallback.
- `capabilities/` can mint the caps a driver declares in its manifest.
- `interrupts/` can bind an IRQ to a driver's UIPI receiver.
- `io/` can mint a DMA context bound to the driver's domain.

## 3. Public interface

Driver manifest (compile-time `#[driver(...)]` macro + runtime-parsed
metadata):

```toml
[driver]
name = "virtio-blk"
domain = "dedicated"
mmio_regions = [{ pa = "...", size = "..." }]
irqs = [16]
caps_required = ["BusDevice", "BlockDeviceBackend"]   # see below
```

**`caps_required` is a typed enum, not a free-form string list.**
The strings in the manifest are parsed against
`capabilities::CapKind` at signature-verification time (before load).
A manifest naming an unknown cap fails verification; this prevents
typos like `"BlockDeviceBackEnd"` from silently granting no access
and surfacing only as a confusing runtime cap-not-held error inside
the driver. The valid set of `CapKind` strings is enumerated in
`capabilities/specification/spec.md` and changes only via Interface-
class PRs per `process/` §4.

Driver trait:

```rust
pub trait Driver: 'static {
    fn start(&mut self, env: DriverEnv<'_>) -> impl Future<Output = ()>;
    fn quiesce(&mut self) -> impl Future<Output = ()>;
}
```

`DriverEnv` carries the caps, MMIO maps, and IRQ handles the kernel
granted based on the manifest.

## 4. Invariants & safety properties

- A driver never holds `Cap<Frame, _>` — the Frame is off-limits.
- Driver panics terminate only that driver's domain, not the kernel.
- Driver storage is in its own domain; cross-domain data is exchanged
  only via Narf-Rings.
- A misbehaving driver cannot starve the global executor (fairness
  guaranteed by `scheduler/`).

## 5. Architecture notes

Arch differences surface per-driver, not at the framework level.

## 6. Dependencies

- **Consumes:** `memory/`, `capabilities/`, `interrupts/`, `io/`, `ipc/`,
  `scheduler/`, `crypto/` (manifest-signature verification at load time),
  `bus/` (device discovery + `Cap<BusDevice, _>` claim), `power/`
  (runtime-PM hooks for quiesce/resume).
- **Provides to:** each concrete driver.

## 7. Stage assignment

Stage 2 (framework), Stage 3–4 (concrete drivers).

## 8. Open questions

- Driver hot-reload: required or defer?
- Manifest signing / integrity — who signs, where is the key rooted?
- Shared vs. per-driver domains for chatty low-risk drivers (console).
- **ELF-microprogram model for drivers (Shiva-inspired).** Treat each
  driver as a PIE ELF loaded into its domain with runtime relocations
  resolved against a capability-populated GOT. Gains: hot-reload, a
  single shared relocation engine with `userspace/`. Decide in Stage 3
  or defer.
