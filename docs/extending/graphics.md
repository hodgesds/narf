# Extending NARF: Graphics — Framebuffer, KMS/DRM, EDID

Prereq: [drivers.md](drivers.md). This covers the display seams at the level a
GPU / display / framebuffer driver plugs into.

There are **three** related surfaces, at increasing capability:

1. **`FbScanout`** (`fb/`) — the scanout backend that the framebuffer console
   and `/dev/fb0` paint into. Simplest; a bootloader FB registers here.
2. **DRM card registry** (`drivers/gpu/`) — a KMS `/dev/dri/cardN` device with
   CRTCs / connectors / encoders.
3. **EDID** (`edid/`) — a pure parser for display capability blocks.

Read the [gotcha about the scanout picker](#4-gotchas-and-the-out-of-tree-gap)
first if you're writing a *new GPU* backend — the active-scanout picker is not
open for out-of-tree extension today.

---

## 1. Framebuffer scanout (`fb/`)

### 1.1 The `FbScanout` trait

`FbScanout` (`fb/src/lib.rs:68`) is the backend a scanout consumer (fb-console,
fbdev) drives. Required methods `width`/`height`/`stride`/`format`/`name`/
`flush`/`framebuffer`; `phys_base` has a default:

```rust
pub trait FbScanout: Send + Sync + core::fmt::Debug {   // fb/src/lib.rs:68
    fn width(&self) -> u32;                              // :69
    fn height(&self) -> u32;                             // :70
    fn stride(&self) -> u32;                             // :71
    fn format(&self) -> PixelFormat;                     // :72
    fn name(&self) -> &'static str;                      // :75  "bochs", "virtio-gpu"
    fn flush(&self, x: u32, y: u32, w: u32, h: u32);     // :79  push rect to host
    fn phys_base(&self) -> Option<u64> { None }          // :86  default; Some = mmap-able /dev/fb0
    unsafe fn framebuffer(&self) -> Framebuffer;         // :97  borrow pixel buffer (cap-gated)
}
```

`flush` is a no-op for direct-FB backends (bochs writes straight to the aperture)
and issues `TRANSFER_TO_HOST_2D` + `RESOURCE_FLUSH` on virtio-gpu.
`framebuffer()` is `unsafe`: the caller must hold `Cap<FbScanoutCap, Write>` and
guarantee no concurrent writer.

### 1.2 The bootloader-FB fast path — `register_generic`

The clean, fully out-of-tree way to publish a display when the bootloader
already set a mode (UEFI GOP, VESA VBE, Limine GOP):

```rust
pub fn register_generic(fb: narf_graphics_driver::generic::GenericFb);  // fb/src/lib.rs:399
```

`GenericFb` (`drivers/graphics/src/generic.rs:9`) is a plain descriptor:

```rust
pub struct GenericFb {           // drivers/graphics/src/generic.rs:9
    pub addr: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u8,
}
```

Build one from your bootloader-provided framebuffer info and call
`narf_fb::register_generic(fb)` in an early initcall. The generic backend is
already wired into the scanout picker (§4) and, in fact, is *preferred* over
native GPU scanouts at boot (`fb/src/lib.rs:497`) because the bootloader already
proved it writable.

---

## 2. KMS/DRM cards (`drivers/gpu/`)

A full mode-setting device (`/dev/dri/cardN`) registers into the DRM card
registry, which lives in **`narf_drivers_gpu` (`drivers/gpu/`)**, not a core
`graphics` crate.

### 2.1 The `DrmCard` trait

`DrmCard` (`drivers/gpu/src/drm_registry.rs:33`) supplies the identity/status
fields the sysfs + devfs bridges need (Linux analogue: `drm_device` +
`drm_driver`):

```rust
pub trait DrmCard: Send + Sync {          // drivers/gpu/src/drm_registry.rs:33
    fn name(&self) -> &str;               // "card0"
    fn driver(&self) -> &str;             // "amdgpu", "bochs"
    fn vendor_id(&self) -> u16;
    fn device_id(&self) -> u16;
    fn subsystem_vendor(&self) -> u16;
    fn subsystem_device(&self) -> u16;
    fn vbios_version(&self) -> Option<&str>;
    fn gpu_busy_percent(&self) -> Option<u32>;
    fn power_state(&self) -> &str;
}
```

### 2.2 Registration + mode-setting state

```rust
pub fn register_drm_card(card: Arc<dyn DrmCard>) -> u32;                 // drivers/gpu/src/drm_registry.rs:108
pub fn register_drm_card_with_state(card: Arc<dyn DrmCard>,             // :124
                                    mode_state: drm::card::Card) -> u32;
pub fn attach_mode_state(index: u32, mode_state: drm::card::Card) -> bool; // :141
```

- `register_drm_card` assigns a 0-based index (→ `/dev/dri/card<N>`); mode state
  is `None`, so `DRM_IOCTL_*` returns `ENOTSUP` until you attach it.
- Build the mode-setting `Card` (`drm::card::Card::new(name, desc, version)`
  with `crtcs` / `encoders` / `connectors` pushed — see the bochs example) and
  either register-with-state or `attach_mode_state(index, kms)` after.

### 2.3 `/dev/dri` node

The devfs bridge installs the `/dev/dri/` directory delegate:

```rust
drm_devfs_bridge::install_dri_dir();      // drivers/gpu/src/lib.rs:313 (Stage::Late)
```

which under the hood calls `narf_filesystem::devfs::register_dri_dir(dir)` (the
directory-delegate char-device pattern — see [chardev.md](chardev.md) §"directory
delegate"). You don't normally call this per-driver; the bridge does it once and
serves every registered card.

### 2.4 Worked reference: bochs DRM card

`drivers/gpu/src/lib.rs:256` (`bochs-drm-card`, `Stage::Late`) builds a
`drm::card::Card` with one CRTC/encoder/connector from the bochs scanout
geometry (`drivers/gpu/src/lib.rs:270-303`), then:

```rust
let idx = drm_registry::register_drm_card(Arc::new(card));   // drivers/gpu/src/lib.rs:305
drm_registry::attach_mode_state(idx, kms);                   // :306
```

`BochsCard` is the `DrmCard` impl (in `drm_devfs_bridge.rs`). amdgpu, intel-gpu,
nvidia, qxl, vmware-svga follow the same shape, each registering a PCI driver at
`Stage::Subsys` (`drivers/gpu/src/lib.rs:217-238`) and building its DRM card at
`Stage::Late`.

---

## 3. EDID (`edid/`)

A pure parser — no registration, no device model. Feed it a raw 128-byte block
fetched over DDC/I2C or DisplayPort AUX:

```rust
impl Block {
    pub fn parse(buf: &[u8]) -> Result<Self, EdidError>;   // edid/src/lib.rs:211
    pub fn preferred_mode(&self) -> Option<DetailedTiming>; // edid/src/lib.rs:322
}
```

`Block` (`edid/src/lib.rs:181`) exposes `manufacturer_id`, `detailed_timings`,
`display_descriptors`; `DetailedTiming` carries `pixel_clock_khz`, active/sync
geometry, and a computed `refresh_mhz()`. `EdidError` is
`BadLength`/`BadHeader`/`BadChecksum`. A GPU driver calls this to enumerate modes
and pick the native resolution.

---

## 4. Gotchas and the out-of-tree gap

- **The active-scanout picker is NOT open for out-of-tree extension.**
  `select_active()` (`fb/src/lib.rs:468`) is a **hard-coded priority chain** over
  a fixed set of backends: test → `GENERIC` → `AMDGPU` → `BOCHS` → `VIRTIO_GPU` →
  `INTEL_GPU` (`fb/src/lib.rs:497-526`). Each arm checks that backend's own
  `is_probed()` + `with_controller(...)` accessor. A **brand-new GPU `FbScanout`
  backend cannot be picked up as the active scanout without editing
  `fb/src/lib.rs`.** The clean out-of-tree paths that avoid this are:
  (a) `register_generic` (your driver programs the mode, then hands the plain
  framebuffer to the generic backend), or (b) register a `DrmCard` for
  `/dev/dri` and let userspace drive KMS. This is the one real driver-facing gap
  in the graphics stack — flagged so you don't burn time implementing
  `FbScanout` expecting the picker to find it.
- **DRM registration lives in `narf_drivers_gpu`, not a core crate.** An
  out-of-tree GPU driver depends on `drivers/gpu` (`narf_drivers_gpu`) to call
  `register_drm_card`. That crate is `pub`, so it works, but note the dependency
  edge.
- **`framebuffer()` is `unsafe` + cap-gated.** Serialise your own writes; the
  returned `Framebuffer` aliases the live scanout.
- **Generic-FB beats native GPU at boot on purpose** (`fb/src/lib.rs:497`) —
  don't be surprised your native scanout isn't selected while a bootloader GOP FB
  is registered; that's a deliberate reliability choice.
- **`no_std`/IRQ.** Registries are `IrqSafeSpinLock`-backed; registration is a
  boot-time event. Do flush/scanout work from a driver task, not an ISR.
