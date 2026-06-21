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
- **Rung 7 (Wayland compositor) — DONE (6 sub-steps).** A real Wayland
  compositor runs multiple unmodified-libwayland GUI client processes on
  NARF, drawing to the screen across process boundaries. Sub-step 1: **AF_UNIX
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
  Sub-step 4 done: **first composited Wayland frame.** `/bin/mini_compositor`
  is a minimal Wayland compositor (wl_compositor/wl_surface/wl_shm) whose
  surface-commit handler reads the client's shared buffer and BLITS IT onto
  /dev/fb0 (Rung 1). An embedded client paints 0x00C0FFEE, passes it via
  wl_shm (SCM_RIGHTS), attaches + commits — and the pixel lands on the
  framebuffer: `comp-ok 1280x800 px=00c0ffee`. The convergence of the whole
  ladder. Final gap fixed: **frame-backed memfd** — MAP_SHARED of a memfd now
  aliases the same physical frames (was an eager private copy), so client +
  compositor share the wl_shm pool. musl-demo CI case. On `main`.
  Sub-step 5 done: **two-process Wayland — the real desktop architecture.**
  /bin/wl_2proc forks a compositor process (named wl socket + event loop,
  blits to /dev/fb0) and a SEPARATE client process; the client's pixel lands
  on the framebuffer across process boundaries: `2proc-ok 1280x800
  px=00c0ffee`. Proves named AF_UNIX connect-by-path, TRUE cross-process
  SCM_RIGHTS fd-passing (the memfd kernel object moves between fd tables),
  cross-process shared memory, and a compositor serving an external client.
  Gaps fixed: stat() of a missing file → ENOENT (was EPERM); socket() masks
  SOCK_CLOEXEC/SOCK_NONBLOCK from the type (libwayland's SOCK_STREAM|
  SOCK_CLOEXEC was read as unknown → bind failed). musl-demo CI case. On main.
  Sub-step 6 done: **multi-window — two apps at once.** /bin/wl_multi forks
  TWO independent client processes; the compositor composites both side by
  side on /dev/fb0: `multi-ok 1280x800 a=00c0ffee b=00bada55`. Concurrent
  multi-client serving (multiple connections / memfds / fd-passing in flight)
  — the hallmark of a desktop running >1 app. Worked first try, no new gaps.
  On main.
- **Rung 8 (xdg-shell window mapping) — DONE.** Core Wayland only moves
  pixels; every real GUI toolkit (GTK/Qt/SDL) maps its top-level window
  through **xdg-shell** (`xdg_wm_base` → `xdg_surface` → `xdg_toplevel`) and
  aborts at startup if the compositor doesn't advertise it. `/bin/wl_xdg`
  forks a compositor advertising `xdg_wm_base` + an independent client that
  drives the full map sequence: create `xdg_toplevel` → initial
  `wl_surface.commit` (no buffer) → server sends `xdg_toplevel.configure` +
  `xdg_surface.configure` → client `ack_configure` → attach a wl_shm buffer +
  commit → the compositor composites the now-mapped window to `/dev/fb0`:
  `xdg-ok 1280x800 px=00c0ffee`. The gateway to running unmodified toolkit
  apps. Built on the libwayland pattern + xdg-shell protocol codegen
  (`REGEN_wl_xdg.sh`); no new kernel gaps (prior transport work covered it).
  musl-demo CI case. On `main`.
- **Rung 9 (wl_seat input delivery) — DONE.** A drawn window is useless if it
  can't receive input. `/bin/wl_input`'s compositor advertises **wl_seat**
  (keyboard+pointer); the client maps an `xdg_toplevel`, binds
  `wl_keyboard`/`wl_pointer`, and once the window is composited the compositor
  synthesises a focus + keypress + click: `keyboard.keymap(fd)` →
  `keyboard.enter` → `key(KEY_A, pressed/released)` → `pointer.enter` →
  `motion` → `button(BTN_LEFT)` → `frame`. The client confirms it received
  `KEY_A`: `input-ok 1280x800 key=30`. This also exercises **`SCM_RIGHTS` in
  the reverse direction** — the keymap fd travels compositor→client (wl_shm's
  buffer fd went client→compositor) — and it worked with no new kernel gaps.
  musl-demo CI case (`REGEN_wl_input.sh`). On `main`. (Wiring the *real*
  evdev `/dev/input/event*` stream into `wl_seat` is the follow-on; it needs
  an input-injection harness, since CI can't generate hardware key events.)

### Kernel-ABI fixes the Wayland stack surfaced (each helps all Linux software)

- `sendmsg`/`recvmsg` **`SCM_RIGHTS`** fd-passing over AF_UNIX (was ignored).
- **Frame-backed memfd** so `MAP_SHARED` aliases the same physical frames
  across mappings/processes (was an eager private copy) — the bedrock of all
  shared-memory IPC (wl_shm, POSIX shm).
- `recvmsg` returns **`-EAGAIN`** (not `-1`→EPERM) on a non-blocking empty read.
- `stat`/`statx`/`newfstatat` of a missing file returns **`-ENOENT`** (not EPERM).
- `socket()` masks **`SOCK_CLOEXEC`/`SOCK_NONBLOCK`** from the type before
  categorising + applies them to the fd.
- `getsockopt(SO_PEERCRED)` returns a (synthetic) ucred.
- `sys_select` reads the user `timeval` through `copy_from_user` (SMAP #PF fix).

### Remaining toward a *usable* desktop (not yet done)

- **Real evdev → wl_seat bridge**: the compositor reads the Rung-2
  `/dev/input/event*` nodes and forwards real hardware events to the focused
  client (the Wayland-side delivery is proven by Rung 9; this wires the
  hardware source). Needs an input-injection harness for CI, since QEMU
  hardware key events can't be generated from the sandbox. Real apps then
  want libinput, which needs a udev shim.
- Present via DRM/KMS page-flip instead of the direct fbdev blit (the Rung-6
  present path) — architecturally-correct presentation.
- An unmodified toolkit app (an SDL2 or GTK program) mapping a real
  `xdg_toplevel` and taking input against our compositor — now unblocked by
  Rungs 8–9.
- A real off-the-shelf compositor (weston `--use-pixman`) + clients, or Xorg +
  `xf86-video-modesetting` + a tiny WM. Likely next kernel gaps: PRIME/dma-buf,
  more `epoll`/`signalfd`/`timerfd` edges, udev enumeration.

Note: the `user-mode-testbin` harness mounts no `/dev`, so device-file
end-to-end proofs run from the **boot-init shell** (`run-interactive` /
`musl-demo`), not the testbin.

---

## Current state (updated 2026-06-20)

All of Rungs 0–7 below have **landed on `main`** — see the Progress section
above for what each delivered and how it's CI-proven. In short, NARF now:

- maps device memory into userspace (the Rung-0 `FileOps::mmap_frames` +
  `sys_mmap MAP_SHARED` keystone);
- exposes `/dev/fb0` (Linux fbdev), `/dev/input/event*` (evdev), and
  `/dev/dri/card0` (DRM/KMS dumb-buffer modeset) — each driven by a real
  musl C smoke;
- runs unmodified **libdrm** (`modetest` enumerates + sets a mode +
  presents + page-flips);
- runs unmodified **libwayland** (libffi + libwayland 1.23 static-musl): a
  Wayland compositor serves **multiple independent GUI client processes**,
  each passing a frame-backed shared buffer over the socket (`SCM_RIGHTS`)
  that the compositor blits to the screen.

The original pre-Rung-0 gaps once recorded here — "no device mmap",
"DUMB_BUFFER returns 0", "card wired to amdgpu" — are all **resolved**. The
card is the bochs/virtio-gpu DRM card; dumb buffers alloc/map/scanout;
`SETCRTC` blits.

The sections below are the **original rung specifications** (kept for
reference / rationale). They describe the work as future TODO; it is all
DONE — read the Progress section for the as-built outcome of each.

---

## Rung 0 — KEYSTONE: shared device mmap  ✅ DONE (original spec below)

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

## Rung 1 — `/dev/fb0` (Linux fbdev) over virtio-gpu  ✅ DONE (original spec below)

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

## Rung 2 — `/dev/input/event*` (evdev) keyboard + mouse  ✅ DONE (original spec below)

- Ensure virtio-keyboard + a virtio-mouse/tablet feed `/dev/input/eventN`
  with proper `struct input_event` records (the devfs_input bridge
  exists — verify the event encoding + `EVIOCG*` ioctls programs probe).
- Add `-device virtio-mouse-pci`/`virtio-tablet-pci` to the QEMU profile.

Verify: program reads `/dev/input/event0`, prints key/pointer events
driven by `xtask run-interactive` keystrokes.

---

## Rung 3 — DRM dumb-buffer path on `/dev/dri/card0`  ✅ DONE (original spec below)

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

## Rung 4 — first real unmodified Linux GUI program  ✅ DONE (modetest; original spec below)

Pick the lightest real client that exercises 1–3 end-to-end. Candidates,
easiest first: `modetest`, a DirectFB/fbdev demo, `fbterm`, or a small
SDL2 (kmsdrm/fbdev backend, software renderer) app. No GPU/GL yet.

Verify: the program runs unmodified from the initramfs/rootfs and draws.

---

## Rung 5+ — the long tail (Rungs 5–7 DONE; the rest scoped later)

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
