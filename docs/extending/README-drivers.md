# Extending NARF — Drivers & Peripheral Subsystems

> **Note to integrator:** this is the *drivers group* stub. Merge its index into
> the top-level `docs/extending/README.md` (written by the core-subsystems
> effort) and then delete this file. It exists only so the two efforts don't
> clobber a shared `README.md`.

Guides for writing **out-of-tree drivers** — new crates that add a driver or
extend a peripheral subsystem *without* modifying core crates.

Start here:

- **[drivers.md](drivers.md)** — the anchor. The initcall registry
  (`narf-init`: `Stage`, `register`, `InitResult`) and the bus/device match
  model (PCIe / virtio / I2C / USB / platform), plus short seams for power,
  crypto, tracing, observability. **Read this first.**

Per-subsystem:

- **[block.md](block.md)** — block devices (`narf-block`) + filesystem drivers
  (`root_mount` factory).
- **[net.md](net.md)** — NIC drivers (`narf_net::Interface`).
- **[input.md](input.md)** — input/HID/evdev (`ROUTER.register_device`, `hid` parser).
- **[graphics.md](graphics.md)** — framebuffer (`FbScanout`), KMS/DRM (`DrmCard`), EDID.
- **[sound.md](sound.md)** — audio streams (`AudioStream`).
- **[chardev.md](chardev.md)** — publishing `/dev/*` nodes (`FileOps` + devfs hooks).

## Where clean out-of-tree extension is NOT currently possible

Flagged in the relevant docs; summarised here as a signal for the maintainers:

- **The initcall wiring line** — a kernel-side aggregator must call your crate's
  `register_initcalls()`; there is no dynamic module discovery. (drivers.md §5)
- **Platform (non-discoverable) devices** — no unified `platform_driver` trait;
  fold discovery + subsystem-registration into a `Stage::Device` initcall.
  (drivers.md §3.4)
- **Crypto** — algorithm-locked; no register-an-algorithm / HW-accel seam.
  (drivers.md §6)
- **The framebuffer scanout picker** (`fb::select_active`) and the **audio
  playback picker** (`audio::select_active_playback`) are hard-coded over a fixed
  backend set — a *new* GPU/audio backend can't be selected without a core edit.
  Clean paths exist around them (`register_generic` FB, `DrmCard` for `/dev/dri`).
  (graphics.md §4, sound.md §3)
- **New `/dev/<name>` categories** beyond the four devfs patterns need a
  `DevDir::lookup` match arm in `filesystem/src/devfs.rs`. (chardev.md §4)
