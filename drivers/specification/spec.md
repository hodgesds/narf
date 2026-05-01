# drivers (framework) — Specification

> Status: **v1.0** (Stage 3 → 4 design lock).

## 1. Purpose & scope

**Owns:**

- The **stable Driver SDK** that every driver compiles against —
  trait, capability types, IRQ surface, MMIO accessors,
  registration macro.
- **ABI versioning** — per-symbol versioning that lets the kernel
  evolve internals without breaking out-of-tree or third-party
  drivers, modelled on `userspace/`'s syscall versioning.
- **Module artifact format** — signed ELF blobs carrying match
  tables, dependency lists, SDK-version metadata, and a digital
  signature.
- **Manifest format** — workspace-level declarative selection of
  which drivers ship statically in the kernel image, which build
  to loadable modules, and which are disabled per profile.
- **Loader + lifecycle** — sign-verify, ABI-check, relocate,
  init, register, quiesce, unload.
- **Capability lifecycle** — every resource a driver holds is a
  cap minted at load by the loader and revoked at unload.
- **Match + dispatch table** — uniform across statically-linked
  and dynamically-loaded drivers.
- **Dependency graph** — module deps with topo-sorted load order.
- **Out-of-tree workflow** — vendors and third parties build
  against the SDK without forking the kernel.
- **User-mode hosting** — the same Driver trait runs in-kernel
  or in a sandboxed user-mode domain; only the loader differs.

**Does NOT own:**

- Bus enumeration (`bus/`) — drivers consume `Cap<BusDevice,_>`,
  they don't walk PCIe themselves.
- DMA buffer allocation (`io/`) — drivers consume `Cap<DmaBuffer,_>`.
- IRQ vector allocation (`interrupts/`) — drivers consume
  `Cap<IrqVector,_>` and use `wait_for_irq()`.
- Per-driver protocol (NVMe, virtio, etc.) — that's each driver
  crate's job.
- Domain allocation policy (`memory/`'s PKS/MTE domain
  multiplexing).

## 2. Design principles

The framework optimises for **scaling to hundreds of drivers**
across a multi-decade kernel lifetime. Five principles drive every
decision:

1. **The SDK is the boundary.** Drivers see only what `narf-driver-sdk`
   re-exports. Internal kernel APIs (`narf-memory::frame::ALLOC`,
   private bus methods, etc.) are not visible. This is the single
   load-bearing decision: it's what lets internals churn freely
   without breaking existing drivers, and it's what makes
   user-mode driver hosting a swap-the-loader change instead of
   a re-architecture.

2. **Each driver is a Cargo crate.** Compilation parallelism,
   incremental builds, and out-of-tree drivers are first-class.
   No mega-crate.

3. **Static and dynamic loading share the same shape.** A driver
   crate emits both a `staticlib` (linked into the kernel image)
   and a `cdylib`-equivalent loadable module from the same
   source. The build manifest selects per-image which path each
   driver takes.

4. **Capability-typed everything.** A driver receives caps for
   every resource it touches; the loader mints them at load and
   revokes at unload. No driver can outlive its caps and no cap
   outlives its driver. This makes unload safety mechanical
   rather than vigilant.

5. **Mirror existing kernel patterns.** ABI versioning mirrors
   `userspace/syscall.rs`'s syscall versioning. Cap revocation
   mirrors the existing `Cap<T,R>` revocation flow. RCU grace
   periods mirror `narf-rcu` already in use elsewhere. Loader
   relocations share `userspace/`'s ELF + relocation engine
   (Shiva-inspired model — see Open Questions).

## 3. SDK boundary

### 3.1 The `narf-driver-sdk` crate

A single crate that re-exports the strict subset of kernel APIs a
driver may legitimately depend on. Drivers' Cargo.toml looks like:

```toml
[dependencies]
narf-driver-sdk = { version = "1.4", default-features = false }
```

Nothing else. Depending on `narf-bus`, `narf-memory`, etc.
directly is a build-time error (CI lint + manifest check).

### 3.2 Surface (categorical)

```rust
// re-exported by narf-driver-sdk:

// Driver trait + lifecycle.
pub use narf_drivers::core::{Driver, DriverEnv, DriverError};

// Capability types — by KIND only, not constructors.
pub use narf_capabilities::{Cap, Read, Write, Grant};
pub use narf_bus::caps::{BusDevice, MsiXTable};
pub use narf_io::caps::{DmaBuffer, alloc_coherent};
pub use narf_interrupts::caps::{IrqVector, wait_for_irq};

// Bus / device descriptor accessors (read-only views).
pub use narf_bus::{BusDevice as BusDeviceInfo, DeviceId, BusKind};

// MMIO + queue primitives.
pub use narf_arch::mmio::{read8, read16, read32, write8, write16, write32};

// Async primitives drivers commonly need.
pub use core::future::Future;

// Match + register surface.
pub use narf_drivers::register::{
    DriverRegistration, MatchTable, register_driver, MatchEntry,
};

// Module identity / metadata macros.
pub use narf_driver_sdk_macros::{driver, match_table};
```

What is **deliberately NOT exposed**:

- Frame allocator (`alloc_frame`, `free_frame`) — only via
  `Cap<DmaBuffer,_>` issued by the loader.
- Page tables / `narf-memory` internals.
- Scheduler internals (`spawn`, `run_until_empty`) — drivers
  don't spawn; they implement Future.
- Lock primitives beyond `IrqSafeSpinLock` — and even that is
  re-exported wrapped so its API can stabilise independently.
- The cap registry (`bootstrap_registry_authority`,
  `claim_device_cap`) — caps arrive in `DriverEnv`, drivers
  don't claim.

### 3.3 SDK enforcement

CI gate (`xtask check-driver-isolation`) verifies that every crate
under `drivers/` has only `narf-driver-sdk` (and its declared
sub-crate dependencies) in its dep tree. The gate has zero
allowlist exceptions. Adding a new symbol to the SDK is an
**Interface-class PR** per `process/` §4 — explicit ABI design
review.

## 4. ABI versioning

Modelled directly on `userspace/syscall.rs`'s syscall versioning
(the user's cited reference). Same pattern, different surface.

### 4.1 Per-symbol versions

Each public SDK symbol carries a version tag. Recipe mirrors
`SYS_VERSION_SHIFT` in `userspace/syscall.rs`:

- The kernel exports symbols under **versioned names** in its
  module-load symbol table: `narf_sdk_alloc_coherent@v0`,
  `narf_sdk_alloc_coherent@v1`, etc.
- A driver compiled against SDK 1.0 imports `@v0`. A driver
  compiled against SDK 1.4 imports `@v0` (unchanged) or `@v1`
  (the v1 of any symbol that bumped). The kernel keeps **both**
  versions wired indefinitely — same contract as `v0` syscall
  handlers staying alive forever.
- Adding `@v1` for an existing symbol = a new export +
  `[[symbol]]` entry in the SDK manifest + a recompile of any
  driver that wants to use it. Old drivers continue resolving
  `@v0` against the unchanged code.
- Dropping `@v0` is a breaking change requiring an SDK-major
  bump (see §4.2) and is gated by the same review process as
  removing a syscall.

### 4.2 SDK semver

The SDK crate carries `(major, minor, patch)`:

- **Major** bumps mean an `@v0` was retired (rare, painful, like
  retiring a syscall). All drivers must rebuild against the new
  major; the kernel refuses to load older majors.
- **Minor** bumps add new symbols or new `@vN` versions of
  existing symbols. A driver built against SDK `M.N` runs on any
  kernel with SDK `M.N'` where `N' >= N`.
- **Patch** bumps are pure docs / soundness fixes — no ABI
  impact.

### 4.3 ABI-check on load

Each module artifact carries a `sdk_version: (u16, u16)` field in
its header. The loader checks:

```text
if module.sdk_major != kernel.sdk_major:        REJECT (major mismatch)
if module.sdk_minor >  kernel.sdk_minor:        REJECT (kernel too old)
otherwise:                                       ACCEPT
```

The loader then resolves each symbol the module imports against
the kernel's versioned export table. Unresolved symbols (driver
imports `@v2` of something the kernel only has `@v0`) are a hard
load failure with a useful diagnostic naming the symbol +
versions.

### 4.4 SDK manifest file

`narf-driver-sdk/sdk.toml` is the single source of truth for
what's in the SDK and at what version:

```toml
sdk_major = 1
sdk_minor = 4

[[symbol]]
name     = "alloc_coherent"
versions = [
    { v = 0, since = "1.0", deprecated = false },
    { v = 1, since = "1.3", deprecated = false },  # added DomainId arg
]

[[symbol]]
name     = "wait_for_irq"
versions = [{ v = 0, since = "1.0", deprecated = false }]

# ... one entry per exported function / type / trait method.
```

The CI gate rejects a PR that:
- Removes a symbol or version not marked deprecated for ≥ 1
  minor cycle.
- Adds a symbol without bumping `sdk_minor`.
- Changes a `@vN`'s signature without bumping to `@v(N+1)`.

The SDK Cargo crate is generated from `sdk.toml`; humans don't
hand-edit the re-export file.

## 5. Module artifact format

### 5.1 File layout

Loadable modules are signed ELF wrapped in a `.narfmod`
container. The container is a single binary file with this
layout:

```text
+0x00  magic       = "NARFMOD\0"             (8 bytes)
+0x08  version     = 1                       (u16, container format)
+0x0A  reserved                              (u16)
+0x0C  header_len  = N                       (u32, bytes)
+0x10  header_bytes (N bytes)                — see §5.2
+0x10+N elf_blob  (sig-covered ELF)          — relocatable shared object
+End-256 signature (Ed25519, 64 bytes) + chain (192 bytes)
```

### 5.2 Header (CBOR-encoded for forward compatibility)

```rust
struct ModuleHeader {
    /// Stable identity. Generated once at crate-creation time;
    /// never changes for the same logical driver.
    identity:   Uuid,

    /// Human name (exact crate name).
    name:       String,

    /// Driver version (independent of SDK version; the driver's
    /// own semver).
    version:    (u16, u16, u16),

    /// SDK version this module was built against. Loader uses
    /// this for the §4.3 ABI check.
    sdk:        (u16, u16),

    /// Match table — each entry tells the bus dispatcher when
    /// to instantiate this driver.
    matches:    Vec<MatchEntry>,

    /// Other modules (by identity + min version) this one needs
    /// loaded first.
    depends_on: Vec<Dependency>,

    /// Exposed services this module provides (used to satisfy
    /// other modules' depends_on entries).
    provides:   Vec<ServiceId>,

    /// Permissions the module requests at load. Loader checks
    /// these against the load-authority cap and the system
    /// policy (allowlist by signing key, denylist for
    /// quarantined drivers, etc.). One entry = one CapKind.
    requests:   Vec<CapKind>,

    /// Free-form key/value: build commit, build host, target
    /// triple, optimisation level. Diagnostic only.
    metadata:   BTreeMap<String, String>,
}
```

### 5.3 Signing

Every module ships signed. Three keys, layered:

1. **Vendor key** — issued to a third party (or the kernel's
   own build) by the **kernel CA root**. Signs the actual
   module blob (Ed25519 over header + ELF).
2. **Kernel CA root** — generated once at kernel install /
   image-build time. Signs vendor keys with a 1-year validity
   and a permissions allowlist (which CapKinds vendor keys may
   request).
3. **Boot-time TPM seal** *(optional, hardware-dependent)* —
   the CA root's public key is sealed against a measured-boot
   PCR set so a compromised bootloader can't substitute a
   rogue CA.

Loader verification flow (in order, each step a hard reject):

1. Parse container, extract signature + cert chain.
2. Verify signature against the embedded vendor key.
3. Verify the vendor key's certificate against the kernel CA
   root.
4. Check the cert's `not_after` against `narf_time::wall_clock`
   (skipped if the system clock isn't monotonic-since-attested
   — falls back to "valid at build time" only).
5. Intersect requested `CapKinds` with what the cert authorises.
6. Compute SHA-256 of the verified blob; reject if it appears
   in the **revocation set** (kernel-bundled, updated via signed
   revocation manifest).

`xtask sign-module` is the canonical signing tool; it consumes
a vendor private key and emits the `.narfmod`. CI signs all
in-tree drivers with a build-time CA whose cert ships in the
default kernel image.

### 5.4 Unsigned development builds

A boot-time flag (`narf.modules.allow_unsigned=1`, gated on
`KERNEL_BUILD == debug`) enables loading unsigned modules. In
release builds this flag is hardcoded off. CI rejects a release
build that even compiles the relaxation path.

## 6. Manifest format

### 6.1 Workspace manifest

A new top-level `narf.toml` (separate from any Cargo file) drives
which drivers ship in which image. Multiple profiles allowed.

```toml
[image.production]
sdk_minor = 4                                # min SDK; kernel will export ≥ this
static = [
    "narf-drivers-virtio-blk",
    "narf-drivers-virtio-net",
    "narf-drivers-nvme",
    "narf-drivers-bochs-display",
]
modules = [
    "narf-drivers-e1000",
    "narf-drivers-xhci",
    "narf-drivers-virtio-gpu",
]
disabled = [
    "narf-drivers-i915",
]
sign_key = "build/keys/in-tree.pem"

[image.minimal]
sdk_minor = 4
static = ["narf-drivers-virtio-blk", "narf-drivers-virtio-net"]
modules = []
disabled = "*"                               # everything else
sign_key = "build/keys/in-tree.pem"

[image.dev]
inherits = "production"
modules += ["narf-drivers-vendor-experimental"]   # additive override
allow_unsigned = true
```

`xtask build --image production` reads the manifest, runs the
selected crates with the right output type, and stitches the
image. Adding a driver to the kernel = `git clone <crate>` +
one line in the manifest. Removing a driver = remove the line.

### 6.2 Out-of-tree drivers

A vendor driver lives in its own Cargo workspace and depends on
`narf-driver-sdk` from crates.io (or a vendored path). To ship
it in an image, the system integrator adds it to their `narf.toml`:

```toml
[image.custom]
inherits = "production"
modules += ["acme-storage-driver"]

[crate.acme-storage-driver]
git = "https://git.acme.example/narf-driver"
rev = "v2.4.0"
```

Cargo resolves it like any other dep. Same SDK, same ABI check,
same signature flow.

### 6.3 Per-driver compile-time manifest

Each driver crate carries a `driver.toml` next to its
`Cargo.toml` declaring metadata that ends up in the §5.2 module
header:

```toml
[driver]
identity = "f8e2c1f0-7c4f-11ee-92b1-7b1a8d02b3e2"  # stable UUID
name     = "virtio-blk"
version  = "1.0.0"

matches = [
    { bus = "pcie", vendor = 0x1AF4, device = 0x1042 },
    { bus = "virtio_mmio", device_id = 2 },
]

depends_on = [
    { service = "virtio-pci-transport", min_version = "1.0" },
]
provides = []

caps_required = [
    "BusDevice", "DmaBuffer", "IrqVector", "MsiXTable"
]
```

The `narf_driver_sdk_macros::driver!` proc-macro reads
`driver.toml`, validates it (CapKind names, UUID format), and
emits both:

- the static-build `inventory!`-style registration the kernel
  picks up at link time, and
- the dynamic-build header bytes embedded in the `.narfmod`
  container.

Same source, same metadata, two outputs.

## 7. Loader + lifecycle

### 7.1 States

A module instance moves through:

```text
LOADED → VERIFIED → RELOCATED → INITIALIZED → REGISTERED → BOUND →
  RUNNING → QUIESCING → UNBOUND → REVOKED → UNMAPPED → DROPPED
```

Each transition is a kernel function returning `Result`. Failures
unwind cleanly: a verify failure releases the loaded blob; an
init failure releases relocations + caps; etc. **No partial
state ever survives a failed transition.**

### 7.2 Load protocol

1. **LOADED.** Caller (boot loader, hot-plug daemon, syscall)
   passes a `Cap<ModuleBlob, _>` referencing the `.narfmod`
   bytes (already in memory, e.g. mmap'd from `/lib/narf/modules/`).
2. **VERIFIED.** §5.3 signing flow. SDK ABI check (§4.3).
   Revocation check.
3. **RELOCATED.** Allocate kernel VM (W^X policy: text RX,
   data RW, no W+X). Copy ELF segments. Resolve relocations
   against the kernel symbol table (`kallsyms` equivalent that
   exports only versioned SDK symbols — non-SDK kernel symbols
   are not resolvable, period). Apply final permissions.
4. **INITIALIZED.** Invoke `module_init()` which the
   `driver!` macro wires up. At this point the module owns
   only its load-handle cap; it has no device caps yet.
5. **REGISTERED.** `module_init()` calls `register_driver()`
   passing its `MatchTable`. The match dispatcher accepts the
   registration and inserts it into the live table.
6. **BOUND.** As bus probe events fire (or, for retroactive
   match, on first probe walk after registration), the
   dispatcher creates a `DriverInstance` per matching device,
   mints the per-instance cap bundle (`BusDevice`,
   `MsiXTable`, `IrqVector`, `DmaBuffer`-allocator,
   per-driver-domain `DomainId`), and calls `Driver::probe(env)`.
7. **RUNNING.** Driver instance is operational.

### 7.3 Unload protocol

Triggered by hot-plug remove, explicit unload syscall, kernel
shutdown, or revocation (e.g. signing key revoked, cert
expired):

1. **QUIESCING.** Loader calls `Driver::quiesce()` per-instance
   (already in `narf-drivers` as `Driver::reset` — extend with
   semantic distinction). Driver stops issuing new ops, waits
   for in-flight ops, releases device-side state.
2. **UNBOUND.** Match dispatcher removes the driver from the
   live table. New probes for matching devices fail-soft (or
   pick up a different match).
3. **REVOKED.** Loader revokes every cap in the instance's
   bundle. Any in-flight kernel-side use of those caps fails
   the cap-check on next access.
4. **UNMAPPED.** RCU grace period waits for any concurrent
   IRQ handler / cap-check holding a reference. After grace,
   loader unmaps the module's text/data, returns frames to
   the allocator.
5. **DROPPED.** Module-handle cap dropped. The module is gone.

The grace period in step 4 is essential: an IRQ for the device
may have been delivered but not yet entered the dispatch
table (between LAPIC delivery and `on_irq` running). Waiting
one RCU period ensures any such "in flight" IRQ has run to
completion before the code that handles it is unmapped.

### 7.4 Failure containment

A driver panic does **not** crash the kernel. The panic
handler maps the panicking task / IRQ context back to the
owning module instance, marks it `FAILED`, and runs the unload
protocol from step 3 (REVOKED) — caps are revoked immediately;
the device stops being usable. The kernel logs the failure +
backtrace; the module's logs / device-state are preserved in a
post-mortem buffer for inspection.

Optional auto-restart policy lives in the manifest:

```toml
[crate.acme-storage-driver]
on_panic = "auto_restart_with_backoff"   # | "leave_failed" | "kernel_panic"
```

Conservative default: `leave_failed`.

## 8. Capability lifecycle

The §7.2 BOUND step mints the per-instance cap bundle. Every
cap in the bundle:

- Has a TTL keyed to the module instance's lifetime.
- Is revocable via the §7.3 REVOKED step.
- Is **non-cloneable across module-instance boundaries** —
  caps minted for instance A cannot be transferred to instance
  B (the cap-framework's existing rights-lattice handles this).
- Has its descriptor entry tagged with the owning instance, so
  the post-revocation cap-check fails O(1).

This is what makes unload safe by construction: there's no way
for a driver to "leak" a cap past its lifetime. If it tried to
stash a `Cap<DmaBuffer,_>` somewhere, the cap-check on use
fails after revocation and the driver gets back `Err(Revoked)`
exactly like a misbehaving userspace process — but it can't
drag the kernel down with it.

## 9. Match + dispatch

### 9.1 Match table

```rust
pub enum MatchEntry {
    Pcie    { vendor: u16, device: u16, class: Option<u32> },
    VirtioMmio { device_id: u32 },
    AcpiHid { hid: &'static str },
    DtCompat { compat: &'static str },
    Catchall,                 // for "I'll match anything" framework drivers
}
```

A driver's `MatchTable` is a `&'static [MatchEntry]`. Static-
linked drivers' tables are aggregated via `linkme` (the same
mechanism the verification harness uses). Loadable drivers'
tables come from the §5.2 header; the loader merges them into
the same dispatcher state on REGISTER.

### 9.2 Dispatch

The bus dispatcher (in `bus/src/driver_match.rs`) walks the
unified table on every device-discovery event (boot probe,
hot-plug arrival). Most-specific match wins (vendor+device
beats vendor+catchall beats catchall). Ties resolve by SDK
version (newer wins), then by registration order.

### 9.3 Per-instance binding

On match, the dispatcher mints the cap bundle (§8) and calls
`Driver::probe(env)`. Probe failure (`Err(NotForMe)`) returns
the device to the candidate list for the next-most-specific
match. Probe success (`Ok(())`) commits the binding —
subsequent matches for the same device skip past it.

## 10. Dependency graph

Modules declare `depends_on` entries naming **services** by
identity, not other modules by name. A service is a logical
capability — `"virtio-pci-transport"`, `"msi-x-allocator"`,
`"block-device-registry"`. Multiple modules may **provide**
the same service; the first one to register wins (or a tie-
break per matched-device-class).

Loader topo-sorts modules by service deps. Cyclic dep =
load-time reject. Missing dep = the module stays in the
PENDING set; it's retried after every subsequent successful
load. If a dep is never satisfied, the module remains pending
forever (logged at boot summary).

This is what lets you split, e.g., the AHCI HBA driver from
its hot-plug-policy driver, or the virtio-pci transport from
each device personality.

## 11. Distribution & boot integration

- **Kernel image:** the §6 manifest's `static` set is
  `staticlib`-compiled into the kernel binary at link time.
  These drivers exist before any filesystem is mounted; they
  bring up the boot disk + init filesystem.
- **Initramfs / boot image:** `modules` set is laid out under
  `/lib/narf/modules/<name>.narfmod` in the boot image. After
  early init, a kernel-side load daemon iterates the directory
  and loads each in dep-graph order.
- **Runtime hot-plug:** when the bus surfaces a device with no
  matching driver, a kernel-side hook fires the `narf-modload`
  user-space daemon (later — Stage 5+) which can fetch
  signed modules from a configured store (local, network)
  and request load via the loader syscall.

The `Cap<ModuleLoader, Grant>` syscall surface is gated to
the init process and any process holding that cap (typical:
the modload daemon, the system updater).

## 12. User-mode driver hosting

The Driver trait is capability-typed: every resource a driver
touches arrives as a `Cap<X, R>` granted by the loader. This
means the **same driver crate** can run in two execution
environments:

- **Kernel mode:** Driver methods called directly from the
  bus dispatcher; caps grant access to in-kernel resources;
  IRQs delivered via `on_irq` to in-kernel `wait_for_irq`
  futures.
- **User mode:** Driver methods called via an IPC bridge from
  a user-mode runtime; caps are user-space cap-handles
  validated by the kernel on each access; IRQs delivered via
  UIPI to a user-mode waker.

The loader picks which based on the manifest:

```toml
[crate.acme-storage-driver]
host = "kernel"      # | "user-mode-domain" | "vm-isolated"
```

`host = "user-mode-domain"` runs the driver in a sandboxed
user-mode process with caps mediated by the kernel. The
driver source is unchanged; the SDK's `wait_for_irq` impl
is swapped at link time (kernel build → in-kernel impl,
user build → IPC-RPC impl).

`host = "vm-isolated"` is a future option: spin up a tiny
VM, pass the device through via VFIO, run the driver in
the VM. Requires VFIO support which is a separate spec.

This is the long-term play: by designing the SDK boundary
strictly from day one, switching a driver from kernel to
user-mode for isolation is a flag flip + redeploy. Retrofitting
this onto a kernel that didn't plan for it is a multi-year
project (every Linux attempt at user-space drivers has
struggled here).

## 13. Invariants & safety properties

- **No driver holds `Cap<Frame, _>`.** Frame allocator is off
  the SDK surface entirely. DMA-able memory arrives as
  `Cap<DmaBuffer, _>`.
- **Driver panics terminate only that driver instance**, not
  the kernel. (Stage 4 work in `frame/`.)
- **A misbehaving driver cannot starve the global executor** —
  scheduler fairness is enforced via per-domain budget caps.
- **Cross-domain data exchange is via Narf-Rings only.** A
  driver can't hand a raw pointer to another driver / the
  kernel; the cap-framework rejects.
- **Module text is W^X.** Loader sets text RX, data RW; no
  page is ever both writable and executable.
- **An unloaded module's caps fail-closed.** Post-revocation
  cap-check returns `Err(Revoked)` deterministically.
- **ABI version is checked before any module code runs.**
  Mismatch → reject before relocation, before init, before
  any side effect.
- **Signature is verified before any module bytes are
  trusted.** Even SDK-version reading happens after sig
  verify (header bytes are inside the signed region).

## 14. Architecture notes

Per-arch differences surface in **driver crates**, not in the
framework. The framework is fully arch-portable: SDK symbols
that have arch-specific implementations (e.g.
`narf_arch::mmio::read32`) are versioned the same way, with
the kernel exporting the right body per build target. A driver
written against `mmio::read32@v0` runs on x86_64 and aarch64
identically.

The loader's relocation engine handles both ELF64 (x86_64) and
ELF64-aarch64 relocations; the supported relocation types are
the standard PIE subset (R_X86_64_RELATIVE, R_X86_64_GLOB_DAT,
R_X86_64_JUMP_SLOT, etc.). The relocation engine is shared with
`userspace/`'s ELF loader (Shiva-inspired model from Open
Question §16, lifted to here).

## 15. Dependencies

- **Consumes:**
  - `memory/` — kernel VM allocator for module text/data;
    PKS/MTE domain allocation per driver instance.
  - `capabilities/` — cap minting + revocation; the rights
    lattice; cap-kind registry (used to validate manifest
    `caps_required` strings).
  - `interrupts/` — IRQ vector allocator;
    `wait_for_irq` future surface.
  - `io/` — DMA buffer allocator; IOMMU context binding.
  - `ipc/` — Narf-Ring primitive (cross-driver / driver-userspace).
  - `scheduler/` — async executor; per-domain budget enforcement.
  - `crypto/` — signature verification (Ed25519, SHA-256).
  - `bus/` — device discovery; `Cap<BusDevice, _>` claim flow;
    match-table dispatcher.
  - `power/` — runtime-PM hooks for quiesce/resume; D-state.
  - `rcu/` — grace periods for unload safety.
  - `time/` — wall-clock for cert expiry checks.
  - `userspace/` — relocation engine (shared); IPC bridge
    (for user-mode hosting).

- **Provides to:** every concrete driver crate, the boot loader,
  the modload daemon, the system updater, the panic-recovery
  subsystem.

## 16. Stage assignment

- **Stage 3 (now):** §3 SDK boundary, §4 ABI versioning, §5.2
  module header, §6 manifest format, §7 loader lifecycle,
  §8 capability lifecycle, §9 match dispatcher, §13
  invariants. Static-only path: drivers are `staticlib`,
  manifest selects which to link.
- **Stage 4:** §5 full module artifact format including
  signing, §7 dynamic load path, §10 dependency graph,
  §11 distribution.
- **Stage 5+:** §12 user-mode driver hosting, §11 hot-plug
  modload daemon, VM-isolated drivers.

The Stage 3 deliverable is enough to ship hundreds of
in-tree drivers; Stage 4 unlocks third-party / out-of-tree;
Stage 5 unlocks user-mode hosting. Each stage is independently
useful; each commits to the SDK boundary, which is the
load-bearing decision.

## 17. Resolved decisions

These are the policy decisions that round out the spec — each
one was an open question in the v0.1 outline; the resolution is
now the contract.

### 17.1 Symbol versioning: trampolines, not in-function dispatch

**Decision:** versioned symbols are real distinct ELF exports
named via the GNU `.symver` directive (or its
`#[link_name = "alloc_coherent@v1"]` Rust analogue), one ELF
symbol per `(name, version)` pair. The kernel's module symbol
table publishes each as a separate entry. Drivers' relocations
resolve against the specific version they imported, with no
runtime dispatch overhead.

When two versions share an implementation (the new version is
purely an additive parameter that defaults to the old behaviour),
both symbols point at the same function body via aliasing — no
duplication, but they remain independently resolvable so the
kernel can later separate them.

**Rationale:** matches Linux's `EXPORT_SYMBOL_VERSION` /
`MODVERSIONS` model, which has worked across decades of kernel
churn. Inline-dispatch (single function with a version arg)
saves a few kilobytes of `.text` but loses native-debugger
backtrace clarity, breaks single-stepping into a specific
version, and makes the kernel ABI surface invisible to standard
ELF tooling. The cost of a few extra symbol-table entries per
SDK call is irrelevant at hundreds-of-drivers scale.

**Builds:** the SDK build (driven by `sdk.toml`) emits an
`asm` shim file with one `.symver` line per `(symbol, version)`
that the kernel `narf-frame` link picks up. CI verifies every
entry in `sdk.toml` has a matching shim and every shim has a
matching entry.

### 17.2 Per-instance capability quota

**Decision:** each driver instance receives a `Cap<Quota,
Spend>` at BIND time (§7.2 step 6). The quota descriptor is a
hard-bounded multidimensional budget:

```rust
pub struct Quota {
    pub max_dma_bytes:        u64,    // sum of live DmaBuffer extents
    pub max_dma_buffers:      u32,    // distinct DmaBuffer caps
    pub max_irq_vectors:      u8,     // distinct IrqVector caps
    pub max_msix_entries:     u16,    // sum of MsiXTable entries
    pub max_kernel_vm_kb:     u32,    // module text + data + dynamic alloc
    pub max_outstanding_ipc:  u32,    // in-flight Narf-Ring messages
}
```

Every cap-minting SDK call (`alloc_coherent`,
`request_irq_vector`, etc.) charges the quota; exhaustion
returns `Err(QuotaExceeded)` deterministically. No silent
backpressure.

**Defaults** are set per `host` mode (kernel-mode drivers get
larger budgets than user-mode-domain drivers because they share
the kernel address space and can't be killed cheaply). Each
driver's manifest may **request** a higher budget in
`driver.toml`:

```toml
[driver.quota_request]
max_dma_bytes = "16 MiB"
max_irq_vectors = 4
```

The loader compares the request against the **cert allowlist**
(§5.3): vendor certs ship with a max-quota tuple; requests that
exceed the cert's authorisation reject at load. In-tree
drivers' build-time CA cert is permissive; third-party certs
can be more restrictive.

### 17.3 Cross-driver IPC wire format

**Decision:** services declared via `provides` carry a
**three-tuple identity**: `(service_id: Uuid, sdk_minor: u16,
wire_version: u16)`. The wire version is independent of both
the SDK version and the driver-crate version — it tracks the
on-the-wire CBOR schema for the service's IPC.

`depends_on` consumers declare a **range**:

```toml
depends_on = [
    { service = "block-backend", wire_min = 1, wire_max = 3 },
]
```

Loader matches against providers whose `wire_version` is in
range; multiple compatible providers are picked by SDK-minor
freshness.

**Wire format itself** is CBOR over Narf-Rings (CBOR is already
used in `.narfmod` headers, so the encoder/decoder is shared
infrastructure — no new format implementation). Each service's
schema is published in `services/<service-id>/schema.cddl`
alongside its driver crate, version-locked.

Old wire versions stay supported by the provider indefinitely,
exactly like SDK `@v0` symbols. A provider may drop a wire
version only after a 2-minor-cycle deprecation window
(announced in `sdk.toml` deprecation entries).

### 17.4 Restart policy

**Decision:** exponential backoff with a hard ceiling, per
**instance** (not per module — different devices' driver
instances have independent failure histories).

```rust
pub struct RestartPolicy {
    pub strategy:    RestartStrategy,    // None | OneShot | Exponential
    pub initial_ms:  u32,                // first-retry delay
    pub cap_ms:      u32,                // upper bound on retry delay
    pub max_failures: u8,                // before transitioning to Failed-permanent
    pub window_secs: u32,                // sliding window for failure counting
}
```

**Defaults** when manifest sets `on_panic = "auto_restart"`:

```toml
restart = {
    strategy = "Exponential",
    initial_ms = 100,
    cap_ms = 3200,         # 100, 200, 400, 800, 1600, 3200, 3200, ...
    max_failures = 8,
    window_secs = 1800,    # 30 minutes
}
```

After `max_failures` panics within `window_secs`, the instance
transitions to `Failed`-permanent. The kernel surfaces this via
a `BusEvent::DriverFailed { instance, reason }` event the
modload daemon can observe; manual intervention (signed reload
command from a privileged process holding `Cap<ModuleLoader,
Grant>`) clears the failure state.

**State machine** is per-instance and lives in the loader
(not in the driver — drivers can't scribble their own restart
counts). The post-mortem buffer (§7.4) is keyed by instance and
preserves the last `N` failure backtraces for inspection,
where `N` is configurable per-system (default 8).

### 17.5 Devicetree hot-plug

**Decision:** a uniform `Cap<DtOverlay, Apply>` surface that
parallels PCIe Native Hot Plug. Userspace (or a kernel-side
hook responding to a platform-specific notification — e.g.
ACPI _Lxx GPE on x86, GIC SPI on aarch64) submits a signed DT
overlay blob via the loader syscall; the kernel parses it,
validates against the live tree, applies the merge, and fires
`BusEvent::DeviceArrived` for each new node — same dispatcher
the static DT walker feeds.

**Removal** is the symmetric path: a `DtOverlay::Remove(NodeId)`
applies a subtree drop, fires `BusEvent::DeviceRemoved` for
each node in the dropped subtree, and the bus dispatcher
schedules the affected driver instances for unbind via the
§7.3 protocol.

**Validation** rejects overlays that (a) duplicate an existing
node's `phandle`, (b) reference compat strings outside the
overlay's own subtree, (c) declare reg/interrupts overlapping
with already-claimed devices. Overlay signature verification
uses the same cert chain as `.narfmod` modules — DT overlay
publishers are vendor-key-equivalent.

This makes DT hot-plug a sibling of PCIe hot-plug, not a
special case: the bus dispatcher's match table doesn't care
how a device arrived.

### 17.6 Module unload during in-flight syscall

**Decision:** two-phase unload protocol with a configurable
drain timeout.

**Phase 1 — drain.** When unload starts (§7.3 step 1
QUIESCING), the module's published service entries are flipped
to `Unloading`. New IPC calls to the module return
`Err(Unloading)` immediately. In-flight calls continue to
completion. A timer is armed for `drain_timeout_ms` (default
5000). Driver-side `Driver::quiesce()` runs in parallel — it
must not block on its own pending IPC, only on hardware state.

**Phase 2 — force.** When the timer fires, any remaining
in-flight calls have their per-call `Cap<IpcChannel,_>` revoked
synchronously. The blocked caller's syscall return path
observes `Err(Revoked)` and unwinds. The driver's RCU grace
period (§7.3 step 4) waits one full epoch after the last
revocation to ensure no in-flight handler is mid-execution.

**Configuration** is per-module in `driver.toml`:

```toml
[driver.unload]
drain_timeout_ms = 5000
on_drain_timeout = "force"   # | "abort_unload"
```

`abort_unload` returns the module to RUNNING state if drain
times out — useful for "I'm stuck and don't trust force-unload
to be safe" drivers. Default is `force` because the cap-check
machinery makes force-unload mechanically safe.

**Caller-visible contract:** a syscall hitting an unloading
module returns `Err(Unloading)` (drain phase) or
`Err(Revoked)` (force phase). Both are recoverable —
caller can retry, which will then pick up the replacement
module if any (§17.7).

### 17.7 Multi-version coexistence + live upgrade

**Decision:** modules are keyed by `(identity: Uuid,
sdk_version, driver_version)`; multiple registrations with the
same identity but different versions can coexist in the match
dispatcher.

**Match priority** when multiple versions could bind a new
device:

1. Most-specific match (vendor+device beats vendor+catchall).
2. Among equal specificity: newest `driver_version` wins.
3. Tie: registration order (earlier wins; deterministic).

**Live upgrade** flow:

1. Load `vNew` of the module via the §7 protocol. It
   registers alongside `vOld` in the match dispatcher.
2. New device arrivals bind to `vNew` (rule 2 above).
3. Existing `vOld` instances continue running their requests.
4. Operator (or auto-policy) issues
   `request_drain(identity, version=Old)`: dispatcher unbinds
   `vOld` from new matches, signals each `vOld` instance to
   `Driver::quiesce()` after its current request completes.
5. As each `vOld` instance completes its drain, the unload
   protocol (§7.3) reclaims its caps + module text. Note that
   `vOld`'s text stays mapped (RCU-pinned by live instances)
   until the last instance drops; `vNew`'s text is mapped
   independently from load time. The two coexist in kernel VM.
6. Once all `vOld` instances drained, `vOld` module fully
   unloads.

**Constraints:**

- The two versions' SDK majors must match (§4.2). Live upgrade
  across an SDK-major bump is impossible — it requires a
  reboot. This is the "you can't change ABI majors at runtime"
  contract, equivalent to Linux's "kernel binary is immutable
  once booted."
- Two versions sharing the same `provides` service must
  agree on at least one wire-version (§17.3). Otherwise the
  load-time wire-compat check rejects.
- Per-instance state (e.g. NVMe namespace metadata) does not
  migrate between versions — `vNew` instances re-discover
  state from the device. Drivers that need stateful migration
  must publish a `migration` entry in their manifest pointing
  at a per-version migration function; the loader runs it
  during the §17.7-step-4 quiesce. (Stage 5 work; not Stage
  3/4 critical path.)

This makes "deploy a fixed driver" a non-disruptive operation
for the running fleet at scale. The cost is carrying both
versions' module text in kernel VM during the upgrade window —
bounded by the `Quota` (§17.2) and reclaimed automatically
once drain completes.

---

With these resolutions, the spec is complete: there are no
"defer to later" decisions blocking the Stage 3 implementation.
Everything that touches the SDK boundary (which is the only
load-bearing decision in the whole spec) is fixed; everything
else can land as Stage 4/5 features without retroactive ABI
churn.

(Section preserved here as a record of the open-question
state; new genuinely-open issues would be added below.)
