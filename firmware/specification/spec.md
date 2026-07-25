# firmware — Specification

> Status: **v0.1** (Stage 6 design draft).

## 1. Purpose & scope

**Owns:**

- The **firmware blob registry** — a name-indexed table of vendor
  firmware images the kernel can hand to a driver at probe time
  (e.g. `qcom/qcnfa765/amss.bin`, `intel/iwlwifi-cc-a0-77.ucode`,
  `amd/acp/sof-rn.ri`).
- The **`Cap<FirmwareBlob, Read>` surface** drivers see — a
  capability-gated read-only handle to a specific blob whose
  bytes live in DMA-coherent memory ready for staging via BHI /
  ACP-DMA / wherever the device's loader expects.
- **Discovery + load policy** — where blobs come from
  (initramfs, root-partition /lib/firmware/, in-tree fallback)
  and how the kernel decides which one a driver gets. Uses the
  Linux hybrid model: initramfs holds only blobs needed before
  root mounts; /lib/firmware/ holds everything else.
- **Signature verification** — every blob is verified against
  the kernel's trusted-firmware-signers root before it can be
  handed to a driver. Unsigned blobs are accepted only when the
  build profile sets `firmware-allow-unsigned` (developer
  builds; never production).
- **Lifecycle** — refcounted load, RCU-protected access,
  unload-on-revoke. A blob's bytes stay resident only while at
  least one cap holds it open.
- **Userspace hot-load surface** — a privileged daemon can
  install or replace a blob at runtime via `sys_firmware_install`,
  cap-gated against `Cap<FirmwareRegistry, Write>`.

**Does NOT own:**

- The **device-side loader protocol** (BHI / SBL / AMSS hand-off
  for QCNFA, iwlwifi's `IWL_UCODE_*` phases, ACP `RI_LOAD`,
  HDA codec firmware patch streams). Each driver crate owns
  the protocol that its silicon understands; this crate only
  hands the driver bytes + a phys address.
- Filesystem decisions (`filesystem/`). Discovery uses the
  filesystem registry — `firmware/` itself is FS-agnostic.
- DMA-coherent allocation (`io/`). Blob bytes land in
  `DmaBuffer`s minted by `narf-io::alloc_coherent`; this crate
  only owns the cap surface that wraps them.
- Driver bring-up (`drivers/`). Drivers query the registry from
  inside their own probe; the framework doesn't gate probe on
  firmware presence — that's a per-driver decision (NIC drivers
  may stay in `Bound` state without firmware; storage drivers
  may not).

## 2. Why this is a separate crate

Firmware loading is a cross-cutting concern that wires three
existing kernel surfaces together (filesystem reads, DMA-coherent
allocation, capability minting) plus signature verification. A
single home prevents three failure modes the kernel has to
prevent:

1. **Inline firmware loaders in driver crates.** If every driver
   reaches into `narf-filesystem::open` directly to pull blobs,
   each driver re-implements path resolution, fallback policy,
   caching, and signature verification — the very pattern the
   `drivers/specification/spec.md` decries with "no driver
   should walk PCIe itself."

2. **Hidden allocation in IRQ-time hot paths.** Real-silicon
   experience (see `feedback_cap_bootstrap_hot_path.md`) is that
   any allocation done per-event grows unbounded. A firmware
   *load* is a one-shot operation that happens once during
   probe; once loaded, blob access is a `Cap<FirmwareBlob, Read>`
   read with no allocation. Putting the registry in one place
   makes that boundary obvious.

3. **Untraceable firmware-version coupling.** When a kernel
   ships, the bound-driver inventory should record exactly which
   firmware blob (sha256 + version string + signer fingerprint)
   each driver bound against. A single registry crate is the
   authoritative source for that record.

## 3. Design principles

1. **Caps in, bytes out.** A driver requests `Cap<FirmwareBlob,
   Read>` by canonical name; the registry returns either the
   cap or `NotFound`. The driver never sees a path, never
   touches the filesystem, never decides which copy of a blob
   wins. This mirrors how `Cap<BusDevice, Write>` walls drivers
   off from PCIe enumeration.

2. **One-shot + RCU-grace unload.** Blobs are typically loaded
   once at driver probe and live until the driver unbinds. Hot
   paths re-borrow the same cap; they don't re-load the blob.
   Cap revocation triggers an RCU grace period before the
   underlying DMA pages are returned to the allocator.

3. **Discovery is policy, not mechanism.** The mechanism is "the
   filesystem registry can resolve `firmware/<name>`." The
   policy — which mount provides those bytes, and how a vendor
   ships an updated package — is set per-build and observable
   via `firmware::source_for(name)`. Splitting policy out lets
   distros deliver firmware via signed packages while
   constrained-flash builds embed blobs directly.

4. **Signed by default.** Production builds reject unsigned
   blobs at the registry layer. The signature root is the
   kernel's trusted-firmware-signers list (managed alongside
   the trusted-driver-signers list owned by `drivers/`).
   Developer builds opt out via the `firmware-allow-unsigned`
   feature flag, which prints a one-line warning at every
   blob hand-out. The signing surface mirrors the module-
   loader signing surface from `drivers/specification/spec.md`.

5. **Mirror existing kernel patterns.** Cap minting +
   revocation matches `Cap<T, R>` lifecycle. Signature
   verification reuses `narf-crypto::verify_ed25519`. Path
   resolution + read goes through `narf-filesystem`. RCU grace
   uses `narf-rcu`. Recording + observability uses
   `narf_drivers::record_bound`-style inventory hooks.

## 4. Public API surface

```rust
/// A loaded firmware blob, addressable by canonical name. Holds a
/// reference-counted handle into the registry's DMA-coherent page
/// pool; the bytes are dropped when the last `Cap<FirmwareBlob, _>`
/// pointing at this entry is revoked.
#[derive(Debug)]
pub struct FirmwareBlob;
impl CapType for FirmwareBlob { const KIND: CapKind = CapKind::Firmware; }

/// Cap-gated registration authority. Held by the firmware-load
/// daemon (or by initramfs unpack code at boot). Bootstrapped once.
#[derive(Debug)]
pub struct FirmwareRegistry;
impl CapType for FirmwareRegistry { const KIND: CapKind = CapKind::FirmwareRegistry; }

/// Errors surfaced by the registry. Mirrors the
/// `narf-bus::ProbeError` shape.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FirmwareError {
    /// No blob registered under this canonical name.
    NotFound,
    /// Blob was found but its signature didn't verify.
    SignatureInvalid,
    /// Blob was found but its declared format isn't one we support.
    BadFormat,
    /// Allocation failed minting the cap.
    OutOfMemory,
    /// The registry authority cap was revoked.
    AuthorityRevoked,
    /// Name is empty, absolute, or contains a `..` component.
    InvalidName,
    /// Caller-provided destination is smaller than the payload.
    BufferTooSmall,
}

/// Read-only blob accessor. Returned by the cap's `view()` method.
/// The slice is valid for the lifetime of the cap.
#[derive(Copy, Clone, Debug)]
pub struct BlobView<'a> {
    /// Canonical name (e.g. "qcom/qcnfa765/amss.bin"). Stable.
    pub name:    &'static str,
    /// Vendor-supplied version string, parsed from the blob's
    /// metadata. None if the format doesn't carry one.
    pub version: Option<&'a str>,
    /// SHA-256 of the blob bytes. Recorded in the bound-driver
    /// inventory so kernel snapshots can correlate driver
    /// behaviour with firmware version.
    pub sha256:  [u8; 32],
    /// Signer fingerprint (Ed25519 public-key hash). None when
    /// the build allows unsigned blobs and this one is unsigned.
    pub signer:  Option<[u8; 32]>,
    /// The bytes themselves, mapped DMA-coherent so the driver
    /// can hand the phys address straight to a device-side loader
    /// (BHI, ACP RI_LOAD, iwlwifi UCODE_*, …).
    pub bytes:   &'a [u8],
    /// Phys address corresponding to `bytes`. Identity-mapped on
    /// kernel-resident builds; userspace-driver builds get a
    /// device-visible IOMMU-translated address.
    pub phys:    u64,
}

/// Look up a blob by canonical name. Returns a fresh
/// `Cap<FirmwareBlob, Read>` on success.
pub fn open(
    name: &str,
    auth: &Cap<FirmwareRegistry, Read>,
) -> Result<Cap<FirmwareBlob, Read>, FirmwareError>;

/// Copy verified firmware into caller-owned storage. Equivalent in
/// purpose to Linux `request_firmware_into_buf()`.
pub fn read_into(
    name: &str,
    auth: &Cap<FirmwareRegistry, Read>,
    dst: &mut [u8],
) -> Result<usize, FirmwareError>;

/// Cap method. Borrows the blob's view; the returned slice is
/// valid until the cap is dropped or revoked.
impl Cap<FirmwareBlob, Read> {
    pub fn view(&self) -> Result<BlobView<'_>, FirmwareError>;
}

/// Install (or replace) a blob in the registry. Cap-gated against
/// `Cap<FirmwareRegistry, Write>`. The supplied `bytes` are
/// validated (signature + format) before the registry accepts
/// them.
pub fn install(
    name:  &'static str,
    bytes: &[u8],
    auth:  &Cap<FirmwareRegistry, Write>,
) -> Result<(), FirmwareError>;

/// Snapshot of the registry — name + sha256 + signer for every
/// loaded blob. Used by `narf-observability` for the kernel's
/// firmware-version report.
pub fn snapshot() -> Vec<BlobIdentity>;
```

Like Linux `request_firmware()`, lookup names may contain embedded
`..` text (for example `foo..bin`) but must not contain a `..` path
component. NARF additionally rejects empty and absolute names so a
request cannot escape the registry namespace.

## 5. Discovery + load order — Linux hybrid model

The registry is populated in four sources, in priority order.
The model mirrors Linux (`linux/drivers/base/firmware_loader/main.c`
`fw_get_filesystem_firmware` for the search-path pattern;
`linux/init/initramfs.c` for the boot-time initramfs include):

1. **In-tree fallback** (lowest priority). A driver crate may
   embed a known-good blob via `include_bytes!`. The blob is
   handed to the registry at the crate's `register_initcalls`
   stage. In-tree blobs are typically permissively-licensed
   reference firmware (e.g. virtio device firmware,
   specifically-permitted vendor blobs). The build profile
   `firmware-no-in-tree` strips them entirely so that
   licence-restricted images always come from one of the
   higher-priority sources.

2. **initramfs** (mid-low priority, `BlobSource::Initramfs`).
   `firmware-scan-initramfs` at `Stage::Late` scans the
   multiboot2 initramfs CPIO for `firmware/*` entries. By
   default the initramfs carries **no firmware** (so Limine can
   allocate it as a multiboot2 module without running out of
   memory on the 1.7 GiB linux-firmware bundle). Use
   `cargo xtask image --initramfs-firmware <glob>` to add blobs
   needed BEFORE root mounts (CPU microcode, early-FB GPU
   firmware, storage-controller quirk blobs). Entries here
   override in-tree fallbacks of the same canonical name.

3. **Root partition** (mid-high priority, `BlobSource::Rootfs`).
   `firmware-scan-rootfs` at `Stage::Late`, registered AFTER
   `root-mount-auto`, walks `/lib/firmware/` on the mounted root
   partition. `xtask image` stages everything NOT matched by
   `--initramfs-firmware` into `target/rootfs-firmware-staging/
   lib/firmware/`; `xtask disk-write-partitioned` copies that
   tree onto the NARF_ROOT ext4 partition. Rootfs entries shadow
   Initramfs entries of the same name (later wins). In ISO-only
   boots (QEMU CD-only, no root partition mounted) this initcall
   returns `NotPresent` — that is documented as OK.

4. **Hot install** (highest priority, `BlobSource::HotInstall`).
   A privileged daemon may call `sys_firmware_install` after boot
   to push an updated blob without rebooting. The hot-installed
   blob replaces any prior entry of the same name; existing
   `Cap<FirmwareBlob, Read>` handles continue to point at the old
   bytes (RCU grace) and re-open to pick up the new one.

Lookup walks priority high → low: `HotInstall` → `Rootfs` →
`Initramfs` → `InTree`. The first match wins. The
`source_for(name)` accessor reports which source served a given
blob so observability tools can audit deployment.

### Build-time firmware split: `--initramfs-firmware`

```
$ cargo xtask image --initramfs-firmware "amd-ucode/*" \
                    --initramfs-firmware "intel-ucode/*"
xtask image: initramfs firmware: 12 entries (4.2 MiB)
xtask image: rootfs firmware:    38214 entries (1696.3 MiB)
```

With no `--initramfs-firmware` flags (the default):
- initramfs carries zero firmware (< 200 KiB for init + shell)
- All of `target/firmware/` goes to the root partition
- Limine can allocate the initramfs as a multiboot2 module

### Deferred items

- **Firmware signature verification on rootfs** — blobs read from
  `/lib/firmware/` are still validated by the NARF trailer parser
  and signature verifier before registration. Signature key
  rotation for rootfs-delivered firmware (A/B partition rollback,
  signed-package updates) is a follow-up.
- **A/B partition for firmware rollback** — single root partition
  is the current layout; a second partition for staged updates is
  a future disk-layout addition.

## 6. Signature model

Every blob carries an embedded signature trailer:

```text
+----------------------------+
|   raw firmware bytes        |
+----------------------------+
|  Ed25519 signature (64 B)   |
|  signer fingerprint (32 B)  |
|  metadata length (4 B LE)   |
|  metadata (variable)        |
|  trailing magic 'NRFW' (4 B)|
+----------------------------+
```

Verification: hash the `raw firmware bytes` with SHA-256, then
verify the signature against the signer's public key, then check
the signer fingerprint against the trusted-firmware-signers list.

The signers list lives in the kernel image as a build-time
constant (mirrors trusted-driver-signers from
`drivers/specification/spec.md` §11). Field updates to the
signers list require a kernel rebuild; this is intentional — a
stolen signing key is a kernel-level security event.

Blob metadata is a small CBOR / type-length-value blob carrying:

- `version`: vendor-supplied version string
- `device_compat`: list of `(vid, did)` pairs the firmware is
  intended for (advisory; the registry doesn't refuse a blob
  whose compat list misses the actual silicon — that's a driver
  concern)
- `min_kernel_abi`: minimum kernel-firmware ABI version

## 7. Userspace driver hosting

Per `drivers/specification/spec.md` §15, drivers may run in user
mode behind cap-mediated syscalls. The firmware registry surface
mirrors that:

- `open(name, &auth)` becomes a syscall the kernel forwards to
  the central registry; the returned `Cap<FirmwareBlob, Read>`
  is mapped into the user driver's cap table.
- `BlobView::bytes` is a pointer into the user driver's address
  space — the kernel maps the underlying DMA-coherent pages
  read-only into the user AS at cap-grant time. This matches the
  shape used for `MmioRegion` and `DmaBuffer` in the userspace
  driver runtime (`drivers/runtime`).
- `BlobView::phys` is the IOMMU-translated address the user
  driver hands to the device — same as `DmaBuffer::phys_addr()`
  in the userspace runtime.

The signature verification step always happens kernel-side. A
user driver never receives a blob that the kernel hasn't already
accepted.

## 8. Observability hooks

- `firmware::snapshot()` returns one entry per loaded blob;
  `narf-observability` rolls this into the kernel's
  bound-driver / system-state report.
- Each driver bind-time call to `firmware::open` records a
  `BoundFirmware { driver_name, blob_name, sha256, signer }`
  tuple in `narf_drivers::record_bound_firmware`. Crash
  bundles include this so reproductions know which firmware
  was loaded.
- The flight-recorder ring (`narf-tracing`) gets a `firmware`
  event class: `Loaded(name)`, `OpenedByDriver(driver, name)`,
  `Revoked(name)`. Useful for diagnosing
  load-order-dependent races.

## 9. Concrete client examples

### QCNFA765 (WiFi 6E) — Stage-6 wifi data plane

```rust
// In drivers/net/src/qcnfa765.rs, after BAR0 + MHIVER read.
let amss_cap = firmware::open(
    "qcom/qcnfa765/amss.bin",
    &firmware_authority,
).map_err(|_| WifiError::FirmwareMissing)?;
let amss = amss_cap.view()?;
// SAFETY: BAR0 mapped, exclusive owner; phys is DMA-coherent.
unsafe { self.bhi_load(amss.phys, amss.bytes.len() as u32)?; }
// MHISTATUS.READY now asserts within ~200 ms.
```

### Intel ACP6.0 (laptop array mic)

```rust
// In drivers/audio/src/acp6.rs, post BAR0 reset.
let ri_cap = firmware::open(
    "amd/acp/sof-rn.ri",
    &firmware_authority,
)?;
let ri = ri_cap.view()?;
// SAFETY: ACP DMA region is identity-mapped; len bounded by
// `ACP_RI_REGION_SIZE`.
unsafe { self.acp_ri_load(ri.bytes); }
```

### Intel iwlwifi (cross-architecture coverage)

```rust
// Driver picks blob name based on subdevice + SKU, queries
// once, walks the embedded UCODE_* sections itself. The
// registry doesn't know what's inside — it just hands the
// bytes over.
let ucode_cap = firmware::open(
    "intel/iwlwifi-cc-a0-77.ucode",
    &firmware_authority,
)?;
self.parse_and_stage_ucode(&ucode_cap.view()?.bytes)?;
```

## 10. Out of scope (Stage-6 follow-ups)

- **Firmware update orchestration** — no rollback safety net for
  in-place firmware updates. A vendor wanting that surface ships
  it in their userspace daemon.
- **Live-migration of bound firmware** — an updated blob doesn't
  hot-rebind running drivers. The driver must voluntarily
  re-open. Fine because firmware updates without a driver
  restart are vanishingly rare.
- **Cross-architecture binary translation** — blobs land
  byte-identical to what the device expects. No
  arch-conditional fixup, no on-the-fly disassembly. If a vendor
  ships a fat blob with multiple sections, the driver picks.
- **Compression / decompression** — blobs land uncompressed. The
  installer is expected to pre-decompress before calling
  `install()`. Reason: keeping the registry simple makes the
  trust boundary smaller (no decompressor in the kernel
  surface).

## 11. Migration plan from the current state

Today drivers either embed firmware via `include_bytes!`
(virtio-gpu icon font, the bochs default-VGA palette) or simply
don't have firmware support (QCNFA765 stops at MHIVER read; the
Intel HDA driver doesn't load codec patches).

Stage-6 lands `firmware/` in three steps:

1. **Crate skeleton + cap types** — empty registry, `open` that
   always returns `NotFound`. Drivers compile against the
   surface but every wifi / audio driver still skips firmware
   load. (1 PR.)

2. **In-tree fallback path + signature verification** —
   `register_initcalls` adds in-tree blobs at `Stage::Subsys`.
   QCNFA765 + Intel HDA + Intel ACP6 grow firmware-load paths
   that succeed only when the in-tree fallback is present.
   (3 PRs, one per driver.)

3. **Linux hybrid model + hot-install paths** — `firmware-scan-
   initramfs` walks the (now-minimal) initramfs at `Stage::Late`;
   `firmware-scan-rootfs` walks `/lib/firmware/` on the root
   partition after `root-mount-auto`; `sys_firmware_install` ships
   for runtime updates. `xtask image --initramfs-firmware` splits
   the firmware bundle between initramfs and rootfs so Limine can
   allocate the initramfs as a multiboot2 module. (2 PRs.)

After Stage-6, `qcnfa765.rs` graduates from "presence-only" to
"WiFi 6E associate + station", `hda.rs` from "controller bring-up
+ stream prep" to "audible playback + capture", and the Intel
ACP6 driver gets its mic-array data plane.

## 12. Open questions

- Should the registry be **kernel-globally** unique or
  **per-domain**? Per-domain matches the rest of the cap model
  but adds a name-resolution dimension drivers don't actually
  want. Lean toward kernel-global with the trusted-signer list
  as the only access gate.
- Is the **ELF-with-`.firmware`-section** packaging idea worth
  the complexity? An alternate to flat blobs is shipping
  firmware as ELF objects with a `.firmware` section and
  metadata in a `.note.NRFW` segment. ELF tooling becomes
  available for free, but the in-kernel verifier grows.
- **Compression**: revisit if the wifi blob sizes (~5 MB
  uncompressed for QCNFA765 AMSS) push the initramfs past a
  pain threshold. Today: out of scope.
