# Extending NARF: Drivers & the Bus/Device Model

This is the anchor document for writing an **out-of-tree driver** for NARF. It
covers the two mechanisms every driver leans on:

1. **The initcall registry** (`narf-init`) — how you get your code run at the
   right point in boot without touching `main`/`bare_main`.
2. **The bus/device match tables** (`narf-bus` and friends) — how a discovered
   device (PCI function, virtio device, I2C target, USB interface) gets bound
   to *your* probe function.

The subsystem seams a bound driver then publishes into
(block/net/input/graphics/sound/char) each get their own doc:

- [`block.md`](block.md) — block devices + filesystem drivers
- [`net.md`](net.md) — NIC drivers
- [`input.md`](input.md) — input/HID/evdev
- [`graphics.md`](graphics.md) — framebuffer / KMS / EDID
- [`sound.md`](sound.md) — audio streams
- [`chardev.md`](chardev.md) — publishing a `/dev/*` node

And the **core** subsystems (filesystem VFS, syscalls, memory, scheduler, IPC,
capabilities) are documented by the sibling docs under `docs/extending/` — see
the [cross-links](#cross-links-to-the-core-subsystem-docs) at the end.

Every API below was verified against the tree; `path:line` citations are exact
at the time of writing. If a signature has drifted, trust the source over this
doc and please update the citation.

---

## 0. The shape of a NARF driver crate

A driver is an ordinary Rust crate that:

- is `#![no_std]` and pulls in `alloc` (NARF has a heap once `Stage::Core` runs);
- depends on `narf-init` (to register a probe), the relevant **bus** crate
  (`narf-bus` for PCIe), and whichever **subsystem** crate it publishes into
  (`narf-block`, `narf-net`, `narf-input`, …);
- exposes a `pub fn register_initcalls()` (by convention) that the kernel's
  driver-wiring calls once, early. Inside it you call
  `narf_init::register(stage, "name", || { … })`.

The in-tree drivers (`drivers/virtio`, `drivers/net`, `drivers/gpu`, `audio`,
`drivers/i2c`, `drivers/usb`, `drivers/fs/*`) are the reference implementations.
None of them are "special": they use exactly the same public registration
functions an out-of-tree crate would.

> **Framekernel note.** NARF drivers run inside PKS/MTE-isolated *domains*, not
> a flat Ring 0 (see `DESIGN.md` §1). Nothing you write here manages that
> directly — the bus layer mints the device/DMA capabilities your probe
> receives, and the domain assignment is recorded as a diagnostic breadcrumb
> (`narf_drivers::record_bound`, `drivers/src/bound.rs:78`). You program the
> hardware; the Frame confines you.

---

## 1. The initcall registry (`narf-init`) — THE core extension mechanism

Source: `init/src/lib.rs`. This crate mirrors Linux's `*_initcall` ordering
*without* linker-section plumbing. Instead of ELF sections and a
`do_initcalls` walker, subsystems tag each call with a **`Stage`** and the
kernel runs every stage in order, calling each registered fn exactly once.

### 1.1 Stages

`Stage` (`init/src/lib.rs:67`) is an ordered enum; higher runs later:

| `Stage`    | Linux analogue      | Typical content                                   |
|------------|---------------------|---------------------------------------------------|
| `Early`    | `early_initcall`    | before the heap; arch-required setup              |
| `Core`     | `core_initcall`     | RCU, scheduler, IRQ dispatch                       |
| `PostCore` | `postcore_initcall` | structures depending on Core                       |
| `Arch`     | `arch_initcall`     | per-CPU bring-up, arch MSRs                         |
| `Subsys`   | `subsys_initcall`   | per-subsystem one-time setup (**registries, hooks**) |
| `Fs`       | `fs_initcall`       | filesystem registration                            |
| `Device`   | `device_initcall`   | **driver probes** (default for ordinary drivers)   |
| `Late`     | `late_initcall`     | post-driver glue, boot summary                     |

The iteration order is `Stage::ALL` (`init/src/lib.rs:80`). The contract
(`init/src/lib.rs:23-25`): **when stage N runs, every initcall in stages `0..N`
has already returned.** Stages are *policy, not enforced* — an `Early` initcall
that touches the heap is still a bug, it just won't be caught for you.

**Which stage do I use?**

- Registering a **bus match table** (e.g. `register_pci_driver` for your
  vendor/device) → `Stage::Subsys`. You want your match entry present before the
  bus walk fires. This is what every in-tree PCI driver does
  (`drivers/gpu/src/lib.rs:215`, `audio/src/lib.rs:436`, `drivers/virtio/src/lib.rs:42`).
- Installing a **subsystem factory/hook** (FS factory, devfs hook) → `Stage::Subsys`
  or `Stage::Fs`.
- A **directly-probed, non-bus device** (ISA, fixed-MMIO, i8042) → `Stage::Device`
  (`drivers/input/src/lib.rs:83`).

### 1.2 Registering

```rust
pub fn register(stage: Stage, name: &'static str, func: InitFn);          // init/src/lib.rs:254
pub fn register_with_budget(stage: Stage, name: &'static str,             // init/src/lib.rs:267
                            func: InitFn, budget_ms: u32);
```

`InitFn` is `fn() -> InitResult` (`init/src/lib.rs:62`). Registration is behind
an `IrqSafeSpinLock`, so you may call it from any context (in practice: BSP
boot). Order **within** a stage is registration order.

Use `register_with_budget` when your probe is legitimately slow (firmware blob
load, AML eval, link training). The budget (`DEFAULT_BUDGET_MS = 500`,
`init/src/lib.rs:128`) is a **warning watchdog, not a kill** — NARF init runs
synchronously on the BSP, so there is no preemption to fire. Exceeding it logs
one line so bring-up can bisect which call ate the boot budget.

### 1.3 The `InitResult` contract

`InitResult` (`init/src/lib.rs:55`) has three variants — this is the whole
failure model:

```rust
pub enum InitResult {
    Ok,                  // completed successfully
    NotPresent,          // feature/device absent — silent skip, NOT a failure
    Error(&'static str), // non-fatal failure — logged, kernel continues
}
```

- Return **`NotPresent`** when your device simply isn't on this machine (no
  matching PCI function, probe found nothing). It is counted separately in the
  stage stats and is not an error. This is the normal path for a driver whose
  hardware is absent — see the i8042 initcall
  (`drivers/input/src/lib.rs:97-104`), which returns `NotPresent` when neither
  init nor IRQ routing succeeds.
- Return **`Error(msg)`** for a real, but non-fatal, failure (device present but
  misbehaving). The kernel logs it and moves to the next initcall. **Do not
  panic** in an initcall for a recoverable condition — the registry exists
  precisely so the kernel is resilient to losing a soft-fail driver
  (`init/src/lib.rs:37-40`). Fatal init (paging, console early-init, frame
  allocator) lives *outside* the registry by design.

### 1.4 What the runtime does with your call

`run_stage(stage)` (`init/src/lib.rs:294`) snapshots the stage's vec (so an
initcall may itself register a *later*-stage probe), times each call, counts the
result into `StageStats` (`init/src/lib.rs:157`), and emits the boot-summary
row. A verbose per-initcall trace is available via `set_verbose_log(true)`
(`init/src/lib.rs:195`) for hang diagnosis — it prints the last initcall name
before silence.

### 1.5 Minimal skeleton

```rust
// my_driver/src/lib.rs
#![no_std]
extern crate alloc;
use narf_init::{InitResult, Stage};

pub fn register_initcalls() {
    // Present the bus match table before the bus walk (Subsys),
    // OR probe a fixed device directly (Device).
    narf_init::register(Stage::Subsys, "mydev-pci", || {
        crate::pci::register_pci_driver(); // adds our PciMatch entry
        InitResult::Ok
    });
}
```

The kernel's boot code must call `my_driver::register_initcalls()` once. For a
*truly* out-of-tree crate this is the single wiring line that has to exist in a
kernel-side aggregator; everything else is your crate. See
[§5, out-of-tree limits](#5-what-is-and-isnt-cleanly-out-of-tree).

---

## 2. The PCIe bus/device match model (`narf-bus`)

Source: `bus/src/driver_match.rs`. This is the analogue of Linux's `pci_driver`
table + `pci_register_driver`. A driver registers a **`PciMatch`** (a predicate
+ a probe fn); a TCB-trusted walk (`probe_all`) finds the best match per device
and calls your probe with a freshly-minted device capability.

### 2.1 The registration entry point

Re-exported as `narf_bus::register_pci_driver` (`bus/src/lib.rs:72`):

```rust
pub fn register(m: PciMatch);   // bus/src/driver_match.rs:169
```

`PciMatch` (`bus/src/driver_match.rs:139`):

```rust
pub struct PciMatch {
    pub name: &'static str, // diagnostics + dedup key
    pub kind: MatchKind,    // the predicate
    pub probe: PciProbeFn,
}
```

`MatchKind` (`bus/src/driver_match.rs:59`) — pick your specificity:

- `VendorDevice { vendor, device }` — exact pair, highest specificity (rank 3).
- `ClassFull { class, subclass, prog_if }` — full class triple (rank 2). Use
  this to distinguish virtio-blk (01:00:00) / AHCI (01:06:01) / NVMe (01:08:02)
  which all share `class == 0x01`.
- `Class { class, mask }` — base-class family (rank 1), e.g. every VGA
  controller. A class backstop should return `ProbeError::NotForThisDriver`
  (below) when the device isn't actually yours.
- `Vendor { vendor }` — any device of a vendor (rank 0, lowest).

Registration is idempotent on `(name, kind)` (`bus/src/driver_match.rs:171`), so
re-registering the same entry (e.g. across hermetic test cycles) replaces rather
than duplicates.

### 2.2 The probe function

```rust
pub type PciProbeFn =
    fn(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), ProbeError>;
    // bus/src/driver_match.rs:134
```

Your probe receives:

- `device: BusDevice` — the discovered device (cfg-space IDs, BAR layout).
- `cap: Cap<BusDeviceCap, Write>` — a **minted authority capability** owned by
  your probe. Stash it in a `static`, hand it to a long-lived task — it is your
  ticket to touch the device's cfg space and BARs.

Return `ProbeError` (`bus/src/driver_match.rs:36`) on failure. Notably:

- `NotForThisDriver` — for a `Class`/`Vendor` backstop that turned out not to
  fit; `probe_all` skips it quietly instead of flooding the log with
  `BadDevice`.
- `BadDevice`, `NoMemory`, `Other(&'static str)` — real failures.

The bus walk `probe_all(&Cap<BusRegistryCap, Grant>)`
(`bus/src/driver_match.rs:197`) is the TCB entry point; you never call it — the
kernel does, holding the registry authority. Your entries are picked up whenever
it runs (and re-runs pick up late registrations).

### 2.3 Worked reference: `virtio-blk-pci`

The smallest complete PCI driver in-tree. Registration
(`drivers/virtio/src/blk_pci.rs:1225`):

```rust
pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-blk-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_BLK_PCI_VENDOR,      // 0x1AF4
            device: VIRTIO_BLK_PCI_DEVICE,
        },
        probe,
    });
}
```

Probe (`drivers/virtio/src/blk_pci.rs:1185`), abridged — note the shape every
PCI probe follows:

```rust
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>)
    -> Result<(), narf_bus::ProbeError>
{
    if CONTROLLER.lock().is_some() { return Ok(()); }        // idempotent
    // 1. Enable the device (MEM_SPACE | BUS_MASTER | INTX_DISABLE):
    narf_bus::pci::set_command(&cap, &device, /* bits */)?;  // bus/src/driver_match.rs via narf_bus::pci
    // 2. Bring the controller up (maps BARs, sets up queues):
    let dev = unsafe { VirtioBlkPci::bring_up(&device, &cap) }
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    *CONTROLLER.lock() = Some(dev);
    // 3. Publish into the subsystem registry (see block.md):
    narf_block::register_block_device("vblk0", Arc::new(VirtioBlkBlockSync) as _);
    // 4. Diagnostic breadcrumb (optional):
    narf_drivers::record_bound(/* ... */);
    Ok(())
}
```

The pattern is universal: **enable → bring-up → publish into a subsystem
registry → return `Ok`**. The "publish" step is what the per-subsystem docs
cover.

And it's wired at `Stage::Subsys` (`drivers/virtio/src/lib.rs:42`):

```rust
narf_init::register(Stage::Subsys, "virtio-blk-pci", || {
    blk_pci::register_pci_driver();
    InitResult::Ok
});
```

### 2.4 The driver-runtime facade (`drivers/runtime`)

`drivers/runtime/src/lib.rs` is a thin facade re-exporting the primitives a
probe needs, so a driver crate depends on one crate instead of five. On the
kernel build (`kernel` feature) it re-exports
(`drivers/runtime/src/lib.rs:57-63`):

- `map_bar(device, idx) -> Result<MmioRegion, MapBarError>` (from `narf-bus`)
- `alloc_coherent(size, domain) -> Result<DmaBuffer, DmaError>` (from `narf-io`)
- `wait_for_irq(vec) -> IrqWaiter` (from `narf-interrupts`)
- `pci::set_command(...)`
- `Lock<T>` = `IrqSafeSpinLock` (kernel) / `Mutex` (userspace)

It introduces **no new traits** — it is a convenience re-export layer. The
userspace variant (`user_rt`) is a stub whose constructors panic ("NoCap") so a
driver linked without the real userspace runtime fails loudly rather than
silently.

### 2.5 The `Driver` lifecycle trait (optional)

Match-based probes can complete synchronously (bring the device up, stash it in
a `static` — what the Stage-3 in-tree drivers do) **or** hand off to the
lifecycle framework. That framework is `narf_drivers::Driver`
(`drivers/src/lib.rs:201`):

```rust
pub trait Driver: Send + 'static {
    fn start<'a>(&'a mut self, env: DriverEnv<'a>) -> DriverFuture<'a>;  // main loop
    fn quiesce<'a>(&'a mut self) -> DriverFuture<'a>;                    // clean shutdown
    fn reset<'a>(&'a mut self) -> DriverFuture<'a> { Box::pin(async {}) } // recovery (default no-op)
}
```

- `start` runs as a scheduler task — your device's async event loop.
- `quiesce` must return in bounded time.
- `reset` (default no-op, so existing drivers stay compatible) is the AER /
  hot-replug / test-teardown recovery hook; a driver holding device state must
  bring the hardware back to post-power-on register defaults.

`DriverEnv<'a>` is `drivers/src/lib.rs:177`; `DriverFuture<'a>` is a
`Pin<Box<dyn Future<Output=()> + Send>>` (`drivers/src/lib.rs:192`). Registering
into this framework is cap-gated (`RegistrationError`, `drivers/src/lib.rs:233`)
and is the path for drivers that need lifecycle management rather than a
one-shot synchronous bring-up. **Most simple drivers do not need it** — the
synchronous `probe` + a spawned pump task is enough.

---

## 3. Non-PCI buses

The same "register a match table at `Stage::Subsys`, get called back with an
authority" shape recurs on the other buses.

### 3.1 virtio

virtio devices are discovered as PCI functions (vendor `0x1AF4`), so a virtio
driver **reuses the PCI match table** above — one `register_pci_driver` per
virtio device type (`drivers/virtio/src/lib.rs:42-47`). The virtio transport
bring-up (`VirtioBlkPci::bring_up`, and the generic
`drivers/virtio/src/lib.rs` probe path) is what turns the raw BARs into
virtqueues. On aarch64, virtio-mmio nodes come from the device-tree walk in
`bus/src/aarch64.rs` rather than PCI.

### 3.2 I2C (`drivers/i2c`)

An I2C *adapter* (a controller that drives a bus) implements the async
`I2cBus` trait (`drivers/i2c/src/lib.rs:74`):

```rust
#[async_trait]
pub trait I2cBus: Send + Sync + core::fmt::Debug {
    async fn transfer(&self, addr: u8, ops: &mut [I2cOp<'_>]) -> Result<(), I2cError>;
    fn name(&self) -> &str;
}
```

and registers it:

```rust
pub fn register_unique(bus: Arc<dyn I2cBus>) -> Arc<dyn I2cBus>;   // drivers/i2c/src/registry.rs:23
```

Reference: the AMD FCH I2C controller probes its adapters and registers from a
`Stage::Device` initcall (`drivers/i2c/src/lib.rs:98`). Device *discovery*
(ACPI, PCI) is adapter-specific; *registration* uses the common trait. An
I2C-attached leaf device (e.g. i2c-HID, a touch controller) is driven on top of
a registered `I2cBus` — see [input.md](input.md).

### 3.3 USB (`drivers/usb`)

USB class drivers register into the **class registry**
(`drivers/usb/src/class_registry.rs`). You supply a static match table and a
probe fn:

```rust
pub type UsbProbeFn = fn(device: Arc<USBDevice>) -> Result<(), UsbProbeError>;
    // drivers/usb/src/class_registry.rs:99

pub struct UsbClassMatch {                       // drivers/usb/src/class_registry.rs:48
    pub vendor_id: u16,
    pub product_id: u16,
    pub class: Option<u8>,      // None = wildcard
    pub subclass: Option<u8>,
    pub protocol: Option<u8>,
}

pub fn register_class_driver(                     // drivers/usb/src/class_registry.rs:130
    name: &'static str,
    matches: &'static [UsbClassMatch],
    probe: UsbProbeFn,
) -> Result<(), UsbProbeError>;
```

After the xHCI stack enumerates a device it calls `dispatch_probe`
(`drivers/usb/src/class_registry.rs:158`), which finds your match and invokes
`probe(Arc<USBDevice>)`. Your probe claims the device (stash the `Arc`), spawns
any async work separately, and returns `Ok(())`. Wildcard `class`/`subclass`/
`protocol` (`None`) let one entry match a whole device class (e.g. HID).

### 3.4 "Platform" (non-discoverable) devices

**There is no unified `platform_driver` abstraction in NARF today.** Fixed /
non-enumerable devices are brought up per-subsystem: they discover themselves
(ACPI namespace walk, device-tree, or a hard-coded probe like i8042 poking
`0x60/0x64`) and then register with the relevant *subsystem* registry
(`i2c::register_unique`, `power::register_source`, `narf_input::evdev::ROUTER`,
…). Each such driver is wired via a `Stage::Device` initcall that does the
discovery and returns `Ok`/`NotPresent`. This is a clean out-of-tree pattern —
it just isn't a single shared trait. If you want a Linux-style
`platform_device`/`platform_driver` match, that abstraction would have to be
added to a core crate first (worth noting as a gap).

---

## 4. IRQ, DMA, and locking rules for probe/driver code

These bite every driver author, so they live here rather than repeated per doc:

- **`no_std` + `alloc` only.** No `std`. The heap exists after `Stage::Core`;
  do not allocate in an `Early` initcall.
- **DMA buffers are cap-gated.** Get them from `alloc_coherent(size, domain)`
  (via `drivers/runtime` or `narf-io`). Never fabricate a physical address; the
  `DmaBuffer` carries the cap + phys handle. Payloads that cross a ring stay
  cap-referenced, not raw pointers (this is what MTE retag relies on).
- **IRQ-context lock discipline.** IRQ handlers must use `IrqSafeSpinLock`
  (re-exported as `Lock` from `drivers/runtime`) and must not block. A common
  pattern for lock-free IRQ dispatch is to store a raw `Arc::as_ptr` in an
  `AtomicPtr` and load it in the ISR (see the i8042 keyboard node,
  `drivers/input/src/i8042.rs`, and [input.md](input.md)). Do **not** call
  `fd::with_table` or any FS-table lock from inside an IRQ or from a
  `FileOps::read/write` — it deadlocks (this is a known NARF footgun; the fix is
  to intercept higher up).
- **Waiting for IRQs from async code.** Use `wait_for_irq(vec)` to get an
  `IrqWaiter` you can await inside a driver task; don't spin.
- **Initcall stage ordering.** If your probe publishes into subsystem X, X's
  registry must already be initialized. Registries init in their own crate's
  `Stage::Subsys`/`Stage::Fs` initcall; ordinary driver probes run at
  `Stage::Device`. Publishing a match table at `Stage::Subsys` (not `Device`) is
  correct because the table just needs to exist before the bus walk — the *walk*
  and your probe run later.
- **Idempotency.** Make `probe` a no-op when the device is already up (the
  virtio-blk `CONTROLLER.lock().is_some()` guard). `probe_all` can run more than
  once, and tests re-probe.

---

## 5. What is (and isn't) cleanly out-of-tree

**Cleanly out-of-tree** (implement a trait / call a `pub` register fn in your
own crate, no core-crate edits):

| Bus / subsystem | Register with                              | Doc |
|-----------------|--------------------------------------------|-----|
| PCIe            | `narf_bus::register_pci_driver`            | this doc |
| virtio          | (reuses PCI)                               | this doc |
| I2C adapter     | `narf_i2c::registry::register_unique`      | this doc |
| USB class       | `usb::class_registry::register_class_driver` | this doc |
| Block device    | `narf_block::register_block_device`        | [block.md](block.md) |
| Filesystem      | `narf_filesystem::root_mount::register_fs_factory` | [block.md](block.md) |
| NIC             | `narf_net::registry().register`            | [net.md](net.md) |
| Input / evdev   | `narf_input::evdev::ROUTER.register_device` | [input.md](input.md) |
| Framebuffer     | `narf_fb::register_generic`                | [graphics.md](graphics.md) |
| Sound           | implement `AudioStream` (+ PCI probe)      | [sound.md](sound.md) |
| Char device     | `devfs::register_*` / `install_*_hooks`    | [chardev.md](chardev.md) |
| Power source    | `narf_power::register_source`              | [§6](#6-briefly-power-crypto-tracing-observability) |
| Tracing probe   | `narf_tracing::table().register`           | [§6](#6-briefly-power-crypto-tracing-observability) |

**Not cleanly out-of-tree today** (would require editing a core crate):

- **The initcall wiring line.** A kernel-side aggregator has to call your
  crate's `register_initcalls()` once. NARF has no dynamic module loader that
  discovers crates at boot, so this one line is unavoidable for a genuinely
  external crate. Everything downstream of it is yours.
- **Platform (non-discoverable) devices** have no shared `platform_driver`
  trait — you fold discovery + subsystem-registration into a `Stage::Device`
  initcall instead (§3.4). Workable, but not a single seam.
- **New crypto algorithms / hardware crypto accelerators.** `crypto/` is
  algorithm-locked with no register-an-algorithm seam (§6). Adding one edits
  `crypto/` directly.
- **New `/dev/<name>` *categories*** beyond the built-in devfs patterns need a
  small `filesystem/src/devfs.rs` edit; the four existing patterns
  (static node / dynamic hook / directory delegate / auto-block) cover almost
  everything (see [chardev.md](chardev.md)).

---

## 6. Briefly: power, crypto, tracing, observability

Short seams for the peripheral subsystems.

### Power (`power/`)

Register a power source (battery / AC adapter) via the `PowerSource` trait
(`power/src/lib.rs:81`) + `register_source`:

```rust
pub trait PowerSource: Send + Sync {          // power/src/lib.rs:81
    fn source_type(&self) -> PowerSourceType;
    fn capacity_percent(&self) -> u8;
    fn is_charging(&self) -> bool;
    fn name(&self) -> &'static str;
}
pub fn register_source(source: Arc<dyn PowerSource>);   // power/src/lib.rs:90
```

Reference impls: `power/src/battery.rs`, `power/src/ac.rs`. DVFS governors / CPU
idle states have **no** published out-of-tree registration seam yet — they are
managed internally from ACPI/MSRs.

### Crypto (`crypto/`)

**No out-of-tree registration.** Crypto is algorithm-centric: algorithms are
zero-sized type-level markers (`KeyAlgorithm`, `crypto/src/lib.rs:95`) and the
primitives are cap-gated free functions (`ed25519_verify` `crypto/src/lib.rs:196`,
`chacha20_seal` `:223`, `hkdf_expand` `:276`, `aes_xts_256_encrypt` `:306`, …).
There is no "register a cipher" hook; adding an algorithm or a hardware
accelerator (AES-NI/SHA-NI) edits the crate directly. Flagged as a gap.

### Tracing (`tracing/`)

Install a probe handler via the `ProbeHandler` trait
(`tracing/src/dispatch.rs:51`) + a cap-gated `register`:

```rust
pub trait ProbeHandler: Send + Sync + 'static {     // tracing/src/dispatch.rs:51
    fn fire(&self, args: ProbeArgs);
}
// on the global table (tracing/src/dispatch.rs:101):
table().register(&cap /* Cap<ProbeHandlerInstall, Grant> */, probe_id, handler);
    // tracing/src/dispatch.rs:120
```

Probe *sites* are static `probe!(provider, name, "argtypes")` macros
(`tracing/src/lib.rs:169`) — you attach a handler to an existing probe id; you
cannot add new probe sites out-of-tree. Reference handler:
`observability/src/lib.rs:578` (`PmuProbeHandler`).

### Observability (`observability/`)

Per-boot, cap-gated: install a panic-time snapshot ring via
`install_panic_snapshot(&Cap<Recorder, Grant>, &'static FlightRing<…>)`
(`observability/src/lib.rs:490`). This is a boot-time singleton install, not a
per-driver registry; there is no out-of-tree per-driver metric/counter
registration at this stage (`Pmu`/`Debugger`/`Diagnostics` cap types exist at
`observability/src/lib.rs:96` but forward to existing subsystems).

---

## Cross-links to the core-subsystem docs

The **core** subsystems are documented by sibling files under `docs/extending/`
(written by the core-subsystems effort). A driver author most often needs:

- **Filesystem / VFS** (`FileOps`, `DirOps`, `FsInstance`, the mount registry) —
  see the filesystem extending doc, and [block.md](block.md) /
  [chardev.md](chardev.md) here, which use those traits.
- **Syscalls** — how a new `/dev` node's `ioctl` surfaces to userspace, and how
  a driver-backed syscall is added, are in the syscalls extending doc.
- **Capabilities** — every registration/probe seam above is cap-gated
  (`Cap<BusDeviceCap, Write>`, `Cap<NetIface, Grant>`, `Cap<MountPoint, Grant>`,
  …). The capabilities extending doc explains minting/deriving/revoking.
- **Memory / IPC / scheduler** — DMA buffers (`narf-io`), the Narf-Ring
  (`narf-ipc` `Producer`/`Consumer`), and `narf_scheduler::spawn` for driver
  pump tasks are covered by their respective core docs.
