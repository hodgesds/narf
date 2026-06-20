# Road to Desktop Linux on NARF (QEMU)

Goal: run **unmodified Linux graphical software** on NARF under QEMU,
building incrementally toward a desktop. NARF is not Linux — it has a
partial Linux-compatible syscall surface (enough today for musl
busybox/coreutils/redis + an OCI container). A full DE (Xorg/Wayland +
GNOME/KDE + Mesa) is years out; this plan is the **dependency-ordered
ladder of runnable milestones** that gets us there one rung at a time.

Each rung ends in something that *boots and runs under `qemu`*, so we
never accumulate unverifiable work.

## Progress

- **Rung 0 (keystone) — DONE.** `FileOps::mmap_frames` + `sys_mmap`
  shared-device dispatch + scanout phys. On `main`.
- **Rung 1 (`/dev/fb0`) — DONE & proven end-to-end.** Device + Linux
  fbdev ioctls; `smoke_fbdev_*` kernel smokes pass; `/bin/fb_smoke`
  (stock musl) opens `/dev/fb0`, `mmap`s it `MAP_SHARED`, draws + reads
  back → `fb-ok` / `fb-geom 1280x800` via `xtask run-interactive`. Wired
  into the `xtask musl-demo` CI case list. On `main`.
- **Rung 2 (`/dev/input/event*`) — DONE.** Real 24-byte Linux
  `input_event` wire format at the node (16-byte internal `EvdevEvent`
  unchanged) + `EVIOCG*` ioctls (version/id/name/bits/abs/grab);
  `virtio-tablet-pci` added to QEMU (keyboard + tablet both probe).
  `smoke_dev_input_*` kernel smokes pass. On `main`.
- Next: **Rung 3** — run an unmodified SDL2 app (fbdev/kmsdrm) from the
  boot-init shell to surface the real ABI gaps toward a compositor.

Note: the `user-mode-testbin` harness mounts no `/dev`, so device-file
end-to-end proofs run from the **boot-init shell** (`run-interactive` /
`musl-demo`), not the testbin.

---

## Current state (2026-06-20)

What already exists:

- **virtio-gpu 2D driver** (`drivers/virtio/src/gpu_pci.rs`) — real
  `GET_DISPLAY_INFO` → `RESOURCE_CREATE_2D` → `SET_SCANOUT` →
  `TRANSFER_TO_HOST_2D`/`FLUSH`; hands back a `narf_graphics::Framebuffer`.
- **virtio-keyboard** + `narf_input` evdev layer; `/dev/input` devfs bridge.
- **font-rendering framebuffer console** (`graphics/`, `fb/`).
- **DRM/KMS scaffold** (`drivers/gpu/src/drm/`): `/dev/dri/card0` +
  `renderD128` nodes; enumeration ioctls (`VERSION`, `GET_CAP`,
  `MODE_GETRESOURCES`, `MODE_GETCONNECTOR`, `MODE_ADDFB2`, `MODE_RMFB`,
  `MODE_GETPLANE_RES`) implemented at struct level.
- `xtask demo` boots a graphical (GTK) QEMU window — but only shows the
  text console today.

The blocking gaps:

- **No device `mmap`.** `FileOps` (`filesystem/src/lib.rs:346`) has
  `read/write/ioctl/poll` but **no `mmap` hook**. `sys_mmap`
  (`userspace/src/handlers.rs:4327`) handles only anonymous (lazy) and
  `MAP_PRIVATE` file (eager copy) — there is **no shared device-memory
  mapping** that maps existing physical/DMA frames into a user AS.
- DRM `DUMB_BUFFER` cap returns 0 — no buffer alloc, no `MAP_DUMB`, no
  `SETCRTC` (nothing actually scans out), no PRIME/dma-buf. Card is
  wired to amdgpu, not virtio-gpu.

---

## Rung 0 — KEYSTONE: shared device mmap  ⚠️ hard, do first, do carefully

Everything graphical depends on userspace getting a CPU pointer to the
scanout buffer whose writes reach the display. This is one focused piece
of kernel plumbing and must not be rushed.

- Add an `mmap` hook to `FileOps`: given `(offset, len, prot, shared)`,
  return the list of **physical frames** (or a region descriptor) to map
  — *not a copy*. Default impl returns `ENODEV`.
- Extend `sys_mmap`: when `fd >= 0` and `MAP_SHARED`, call the fd's
  `FileOps::mmap` and `map_region` those physical frames into the user AS
  with the right perms (shared, write-through to device memory). Add the
  page-cache-coherency / cache-attribute handling the FB needs (WC).
- Track the mapping so `munmap` tears it down without freeing
  device-owned frames.

Verify: a tiny in-tree user program mmaps a test device node and a
kernel-side check confirms its writes land in the backing frames.

---

## Rung 1 — `/dev/fb0` (Linux fbdev) over virtio-gpu

Simplest standard Linux graphics ABI; proves the keystone end-to-end.

- New char device `/dev/fb0` backed by the live virtio-gpu scanout
  `Framebuffer` (geometry from `GET_DISPLAY_INFO`).
- Ioctls: `FBIOGET_VSCREENINFO`, `FBIOGET_FSCREENINFO`, `FBIOPUT_VSCREENINFO`
  (accept-no-op), `FBIOPAN_DISPLAY`, `FBIOBLANK`.
- `mmap` hook returns the scanout's physical frames (Rung 0).
- A flush strategy: either flush-on-`msync`/`FBIO_WAITFORVSYNC`, or a
  periodic damage-flush task calling `TRANSFER_TO_HOST_2D`+`FLUSH`.

Verify: unmodified musl program mmaps `/dev/fb0`, writes a gradient,
QEMU GTK window shows it. New `xtask fb-smoke` boots + screendumps +
asserts a known pixel.

---

## Rung 2 — `/dev/input/event*` (evdev) keyboard + mouse

- Ensure virtio-keyboard + a virtio-mouse/tablet feed `/dev/input/eventN`
  with proper `struct input_event` records (the devfs_input bridge
  exists — verify the event encoding + `EVIOCG*` ioctls programs probe).
- Add `-device virtio-mouse-pci`/`virtio-tablet-pci` to the QEMU profile.

Verify: program reads `/dev/input/event0`, prints key/pointer events
driven by `xtask run-interactive` keystrokes.

---

## Rung 3 — DRM dumb-buffer path on `/dev/dri/card0` over virtio-gpu  ⚠️ hard

The modern path (what Wayland/X/Mesa use). Reuses Rung-0 mmap.

- Point card0 at a **virtio-gpu DRM backend** (not amdgpu) under QEMU.
- Implement `MODE_CREATE_DUMB`, `MODE_MAP_DUMB` (returns mmap offset),
  `MODE_DESTROY_DUMB`; flip `DUMB_BUFFER` cap to 1.
- `MODE_ADDFB`/`ADDFB2` ties a dumb buffer to a virtio-gpu resource;
  `MODE_SETCRTC` does `SET_SCANOUT` so it becomes visible.
- `GEM_CLOSE`, basic `MODE_PAGE_FLIP` (flush) for double-buffering.

Verify: `libdrm`'s `modetest -s` (unmodified) sets a mode and shows test
pattern; `xtask drm-smoke` screendumps + asserts.

---

## Rung 4 — first real unmodified Linux GUI program

Pick the lightest real client that exercises 1–3 end-to-end. Candidates,
easiest first: `modetest`, a DirectFB/fbdev demo, `fbterm`, or a small
SDL2 (kmsdrm/fbdev backend, software renderer) app. No GPU/GL yet.

Verify: the program runs unmodified from the initramfs/rootfs and draws.

---

## Rung 5+ — the long tail (each a major effort, scoped later)

- **dma-buf / PRIME** export+import (compositor ↔ client buffer sharing).
- **Mesa software** (swrast/llvmpipe) on the render node → GL without HW.
- **Wayland**: `libwayland` + a pixman-renderer compositor (weston
  `--use-pixman`, or a minimal wlroots-pixman compositor).
- **dbus / udev-shim / logind-shim / fontconfig / freetype** as clients
  hit them.
- A minimal DE / panel. (GNOME/KDE remain out of scope.)

Hardware-accelerated GL/Vulkan via a real amdgpu command-submission path
is a separate, much larger track (the existing `amdgpu_*` files) and is
**not** required for a software-rendered desktop.

---

## Verification harness (cross-cutting)

- Extend `xtask` with graphical smokes that boot, drive input via stdin
  (as `run-interactive` does), then use QEMU monitor `screendump` to
  capture the framebuffer and assert known pixels / regions.
- Each user-side test program prints serial success markers too, so
  failures localize without pixel diffing.

---

## Work breakdown for parallel agents

**Keystone (NOT parallel — one careful change, land first):**
- Rung 0 device-mmap plumbing.

**Parallelizable / Sonnet-suitable once Rung 0 lands:**
- Rung 1 `/dev/fb0` char device + fbdev ioctl structs (mechanical UAPI
  struct mirroring from Linux headers).
- Rung 2 evdev event encoding + `EVIOCG*` ioctls + QEMU mouse device.
- Rung 3 DRM dumb-buffer ioctl structs (`drm_mode_create_dumb`,
  `map_dumb`, `destroy_dumb`) — mechanical UAPI mirroring.
- Userspace test programs (gradient-to-fb0, evdev-dump, modetest-style).
- `xtask` graphical smoke subcommands + screendump assertion helper.

**Needs care (kernel internals, not pure-mechanical):**
- Rung 3 virtio-gpu DRM backend + SETCRTC→SET_SCANOUT wiring.
- Cache-attribute / flush correctness for the mmap'd scanout.
