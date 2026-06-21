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
- **Rung 3 (DRM/KMS dumb-buffer modeset) — DONE & proven end-to-end.**
  `/dev/dri/card0` now answers the modeset path: `GET_CAP(DUMB_BUFFER)`,
  `MODE_CREATE_DUMB`/`MAP_DUMB`/`DESTROY_DUMB`, `ADDFB2`, `SETCRTC`/
  `PAGE_FLIP`, `GEM_CLOSE`. `MAP_DUMB`+`mmap` reuse the Rung-0 keystone;
  `SETCRTC` blits the dumb buffer into the active scanout (`fbdev_info`).
  `/bin/drm_smoke` (stock musl) runs the whole open→CREATE_DUMB→mmap→draw
  →ADDFB2→SETCRTC chain → `drm-ok` / `drm-geom 256x256` via
  `xtask run-interactive`; wired into the `musl-demo` CI list. On `main`.
  (Three boot-time bugs the agent's `cargo check` missed were fixed:
  initcall stage ordering, missing SMAP brackets in the ioctl copy
  helpers, and discarded GET_CAP/ADDFB2 results.)
- **Rung 4 (real libdrm client) — DONE & proven end-to-end.** `modetest`
  (libdrm 2.4.134, static-musl, vendored + REGEN script) enumerates
  `/dev/dri/card0` via real libdrm: `drmOpenByName` + VERSION open it,
  then GETRESOURCES / GETCONNECTOR / GETENCODER / GETCRTC /
  OBJ_GETPROPERTIES list Encoders, Connectors (Virtual-1, 1280x800@60),
  CRTCs, Planes, Framebuffers — clean exit. Surfaced + fixed real ABI
  gaps (connector_id offset, missing GETCRTC/GETENCODER, NULL-property
  cleanup crash). `modetest -M narf-drm` is a `musl-demo` CI case
  (anchors on `(1280x800)`). On `main`.
- **Rung 5 (first real display output) — DONE & proven.** `modetest -s
  3@1:1280x800` (real libdrm) sets a video mode and presents an SMPTE test
  pattern through the full present path: CREATE_DUMB → draw → ADDFB2 →
  SETCRTC (blit to scanout). Serial: `setting mode 1280x800-60.00Hz on
  connectors 3, crtc 1`, no errors. Gaps fixed: empty mode `name`, three
  typo'd DRM fourcc constants (XR84→XR24 etc. — drm_smoke + smokes shared
  the same wrong value so they passed; real libdrm exposed it), SETGAMMA
  no-op. `modetest -s` is a musl-demo CI case (anchors on `crtc 1`). On
  `main`. (Pixel-level screendump verification blocked by the sandbox
  killing backgrounded QEMU; serial proof + suite stand.)
- **Rung 6 (compositor render loop) — DONE & proven.** DRM page-flip
  event delivery: `PAGE_FLIP` with `DRM_MODE_PAGE_FLIP_EVENT` queues a
  `drm_event_vblank` (FLIP_COMPLETE); the DRM fd is pollable (`POLL_IN`)
  and `read()` drains the event — the exact present loop weston/Xorg use.
  Plus `SET_MASTER`/`DROP_MASTER` no-ops, and a real `sys_select` #PF fix
  (user `timeval` read without SMAP bracket). Proven: `modetest -v` runs a
  continuous page-flip loop at ~44 Hz (`freq: 44.07Hz` …). Bounded
  `smoke_drm_flip_event_format` in CI. On `main`.
- **Rung 7 (compositor) — STARTED.** Sub-step 1 done: **AF_UNIX
  `SCM_RIGHTS` fd-passing** — the Wayland transport primitive (clients
  pass shm/dma-buf fds over the socket). `sendmsg`/`recvmsg` now parse
  `msg_control`, resolve/install fds across the fd table, and write the
  cmsg back. Proven by `/bin/scm_smoke` (passes stdout over a socketpair,
  writes `scm-ok` THROUGH the received fd). musl-demo CI case. On `main`.
  Sub-step 2 done: **libwayland runs on NARF.** libwayland 1.23 + libffi
  (static-musl) — a client connects to a server over a socketpair and
  completes the wl_display/wl_registry handshake, receiving the
  wl_compositor global. Proven by `/bin/wl_handshake` → `wl-ok`. Surfaced
  + fixed `getsockopt(SO_PEERCRED)` (wl_client_create) and `recvmsg`
  returning `-EAGAIN` for WouldBlock (not the EPERM-mapped `-1`).
  musl-demo CI case. On `main`.
  Sub-step 3 done: **wl_shm buffer sharing.** A client memfd_create()s a
  pool, draws, and hands the fd to the server via wl_shm.create_pool
  (marshalled over the socket with SCM_RIGHTS); the server mmaps it — the
  compositor can now see a client's pixel buffer. Proven by `/bin/wl_shm`
  -> `shm-ok` (no new kernel gaps — the SCM_RIGHTS work paid off). On main.
  Remaining sub-steps: composite the client buffer into a DRM dumb buffer +
  page-flip (Rungs 3/6); libinput over evdev (Rung 2); a real compositor +
  client (weston-pixman or a minimal custom one) actually painting a window.
- The actual compositor. The DRM/KMS present loop + evdev input + the
  Wayland fd-transport are now in place, so the remaining work is the big
  userspace build —
  libwayland (+libffi) + a pixman-software compositor (weston `--use-pixman`
  or a minimal wlroots/custom compositor) + a Wayland client, OR Xorg +
  `xf86-video-modesetting` + a tiny WM. Likely next kernel gaps: PRIME/
  dma-buf for client buffer sharing, more `epoll`/`signalfd`/`timerfd`
  edge cases, and the Wayland Unix-socket fast paths.

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
