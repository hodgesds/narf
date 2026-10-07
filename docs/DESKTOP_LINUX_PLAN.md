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
  musl-demo CI case (`REGEN_wl_input.sh`). On `main`.
- **Rung 10 (KMS page-flip presentation) — DONE.** The earlier compositors
  blitted client pixels straight into a `/dev/fb0` mmap; a real stack
  (weston/Xorg) drives DRM/KMS instead. `/bin/wl_kms` opens `/dev/dri/card0`,
  allocates a full-screen scanout dumb buffer (`CREATE_DUMB` → `ADDFB2` →
  `SETCRTC`), runs an xdg-shell compositor, and on the client's commit
  composites into the *dumb buffer* (never `/dev/fb0`) then `PAGE_FLIP`s the
  CRTC with `DRM_MODE_PAGE_FLIP_EVENT` and `read()`s the `drm_event_vblank`.
  Verification reads `/dev/fb0` **read-only**: the pixel is only there because
  the page-flip presented it. `kms-ok 1280x800 px=00c0ffee flip=1`. **This
  caught a real latent kernel bug:** `fork` was COWing `MAP_SHARED` regions, so
  a compositor that mmaps a device then forks rendered into a private copy —
  fixed (`fork` now keeps SHARED regions shared; the earlier compositors
  masked it via self-readback). musl-demo CI case. On `main`.
- **Rung 11 (real evdev → wl_seat bridge) — DONE.** Rung 9 delivered
  *synthetic* wl_keyboard events; this bridges *real* Linux evdev records.
  Added a Linux-compatible **`/dev/uinput`** kernel device (the mechanism
  ydotool/wtype use). `/bin/wl_evdev`'s compositor creates a virtual keyboard
  via `/dev/uinput`, injects `KEY_A`, and the kernel evdev router delivers it
  as 24-byte `input_event` records on a fresh `/dev/input/eventN`; the
  compositor **reads that node** (real evdev wire), translates the `EV_KEY`,
  and forwards it over `wl_keyboard` to the mapped client: `evdev-ok 1280x800
  key=30`. The compositor can't tell uinput from a USB keyboard — same path.
  musl-demo CI case + a `smoke_uinput_loopback` kernel smoke. On `main`.
- **Rung 12 (first unmodified off-the-shelf GUI app) — DONE.** Every prior
  test used a hand-written client; this runs an **actual upstream binary** —
  weston 9.0's `clients/simple-shm.c`, vendored verbatim as `/bin/simple_shm`,
  linked against stock libwayland. `/bin/wl_app` is the compositor/launcher:
  it advertises `wl_compositor`/`wl_shm`/`xdg_wm_base`, `fork`+`execve`s
  `/bin/simple_shm` with `WAYLAND_DISPLAY` set, sends the configure that makes
  it draw, answers `wl_surface.frame` callbacks so its animation loop runs,
  and composites its first real frame: `app-ok 1280x800 win=250x250` (250×250
  = simple-shm's actual surface). A real toolkit client maps + renders on NARF
  with zero awareness it isn't Linux. musl-demo CI case. On `main`.
- **Boot a real Linux distro — and the desktop inside it — DONE.** NARF mounts
  a real **Alpine Linux 3.21** rootfs (ext2 on the QEMU virtio-blk disk) at
  `/mnt`. `/bin/distro_init` `chroot`s into it and execs Alpine's OWN busybox
  (unmodified, dynamically linked against Alpine's OWN musl resolved under the
  chroot — the container model): `cat /etc/os-release` prints the Alpine
  release and `uname -sm` prints `NARF x86_64`. `/bin/distro_desktop` goes
  further and runs the **Wayland desktop from inside the distro** — the kernel
  bind-mounts `/dev` into `/mnt/dev` and mounts a writable `/tmp`, then the
  launcher chroots and runs our compositor + the unmodified weston-simple-shm
  (placed in the Alpine image) against Alpine's musl: `app-ok 1280x800
  win=250x250`. Two FS fixes made the distro usable (see below). The 28 MiB
  rootfs is built by `REGEN_alpine_rootfs.sh` (not committed / not an auto CI
  case — it displaces the virtio-blk content smoke). On `main`.

- **Rung 13 (stock Fedora + systemd as PID 1) — DONE.** The Alpine/busybox
  chroot above proved a distro's *userland*; this boots a real **Fedora 43**
  image with **systemd as PID 1** — units, targets, journal, D-Bus,
  `systemd-udevd` with a populated device database, seats, and a
  `systemd --user` manager for the desktop user. `distro_fedora` is the
  launcher; the kernel hands systemd the real cmdline via
  `SYSTEMD_PROC_CMDLINE`, and an xtask acceptance gate covers systemd-PID1
  networking (qemu-net + netns). The image is built by
  `REGEN_fedora_kde_rootfs.sh` and is not committed, so this is a local /
  marker-gated gate rather than an automatic CI case.
- **Rung 14 (desktop audio: stock PipeWire + WirePlumber) — DONE, one defect
  open.** Unmodified Fedora PipeWire 1.4 and WirePlumber 0.5 build a complete
  audio graph on NARF: both QEMU cards reach udev's database with the
  properties `spa_alsa_udev` needs, WirePlumber attaches as a second process
  over the PipeWire protocol, builds ACP card profiles, activates routes, and
  exports sinks and a source that `wpctl status` lists. Five Linux-ABI defects
  it surfaced are fixed (`/dev/snd` node ownership, `/proc/<pid>/root` rendered
  in the reader's root frame, followable magic links, per-thread
  `task/<tid>/{stat,comm}`, codec-reported HDA formats). **Open:**
  WirePlumber's main thread burns ~100% of one CPU once the graph is built;
  the gate reports it every run rather than failing on it. Details and the
  elimination list: `verification/data/pipewire-compat/README.md`.
- **Rung 15 (KDE Plasma session) — IN PROGRESS, the current frontier.** The
  Fedora image runs a real Plasma Wayland session under `systemd --user`:
  `distro_kde` chroots and execs the session, and a process-level oracle
  (`fedora-plasma-probe.sh`) watches `kwin_wayland`, `plasmashell`, `kded`,
  `kcminit` and `ksmserver`, emitting `PLASMA-READY` when kwin_wayland and
  plasmashell both survive 10 s and `PLASMA-BLOCKED` otherwise. A long tail of
  guards and taps sits beside it (`fedora-journal-tap.sh`,
  `fedora-udev-seat-gate.sh`, `fedora-drm-policy.sh`,
  `fedora-kcminit-wayland-guard.sh`, `fedora-xkbcomp-capture.sh`,
  `fedora-xrdb-guard.sh`, …), each one a defect that was chased down. This is
  **not** a closed result: Plasma is deliberately excluded from the audio gate
  (`ConditionKernelCommandLine=!narf_audio_check`) because a Plasma process
  taking a fatal fault left the guest spinning and cost that gate its verdict.
- **Rung 16 (native AMDGPU display) — IMPLEMENTED, never run on silicon.**
  Separate from the QEMU ladder above: a Stage::Late worker
  (`amdgpu_usbc::start` → `amdgpu_platform::start`) boots DMCUB through the
  Phoenix PSP 13.0.4 GPCOM ring, discovers sinks, derives timing from EDID,
  runs a fixed-point DML port for watermarks and prefetch, programs the
  DCN 3.1.4 pipeline (OTG, HUBP, DPP, MPC, OPP, DP stream encoder), trains the
  link, and publishes a scanout that `narf_fb` adopts — including tunnelled
  USB4 sinks and replay across suspend. **Nothing in this path has executed on
  real hardware**; see `docs/notes/2026-10-07-amdgpu-status.md`.

### Kernel-ABI fixes the Wayland stack surfaced (each helps all Linux software)

- **`stat` works on a mounted on-disk rootfs**: `stat`/`lstat`/`statx` drove
  the *sync* VFS resolver, but ext2 (any block FS) stubs sync `lookup`, so
  `stat` missed every on-disk file while `open`/`execve` (async resolver)
  found it — busybox `PATH`-probes applets with `stat`, so every applet looked
  "not found". `stat` now drives the async resolver like the open path.
- **ext2 fast-symlink read**: a fast symlink (≤60-byte target inline in the
  inode, e.g. Alpine's `/bin/cat`→`/bin/busybox`) read back empty because
  `FileOps::read` walked data blocks; the VFS reads symlink targets via
  `read`, so every applet symlink was unresolvable. ext2 `read` now serves
  symlink inodes from the inline/data target.
- **`fork` keeps `MAP_SHARED` regions shared** (was COWing them): a process
  that mmaps a device (framebuffer, DRM dumb buffer) or POSIX shm then forks
  now keeps writing the real frames in both parent and child — essential for
  the compositor-forks-client architecture. Caught by Rung 10's KMS readback.

- **`fork` keeps `MAP_SHARED` regions shared** (was COWing them): a process
  that mmaps a device (framebuffer, DRM dumb buffer) or POSIX shm then forks
  now keeps writing the real frames in both parent and child — essential for
  the compositor-forks-client architecture. Caught by Rung 10's KMS readback.
- **`/dev/uinput`** virtual-input device (`UI_DEV_CREATE`/`UI_SET_*BIT` +
  24-byte event injection via `write`), registering a device with the evdev
  router so it appears as `/dev/input/eventN`. Enables userspace input
  injection (Rung 11).
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

The ladder's original question — can unmodified Linux graphics software run
at all — is answered. What is left is a different question: does a *whole
desktop session* stay up and stay responsive.

- **A Plasma session that stays alive** (Rung 15). `PLASMA-READY` is the
  oracle; getting it green and keeping it green is the frontier. The failures
  are no longer "feature absent" but "process faults / hangs under load",
  which is a harder and less mechanical class of bug.
- **The WirePlumber spin** (Rung 14). A silent dispatch loop at ~100% of one
  CPU with every functional stage passing. Narrowing it wants a tracer, and
  `strace -p` currently blocks in `wait4` because a tracee's attach-stop is
  never reported to a tracer that did not fork it. **Reporting that stop is
  the concrete next step**, and it unblocks diagnosis generally.
- **Richer / GPU clients.** A toolkit app beyond simple-shm, then GL via
  Mesa-swrast on the render node. Likely next gaps: PRIME/dma-buf export and
  import between compositor and client, and more `epoll`/`signalfd`/`timerfd`
  edges.
- **Pointer and touch from real hardware,** fed to libinput rather than
  translating `EV_*` by hand.
- **Silicon.** Everything above is QEMU. The Stage 5 laptop gate — boot from
  USB on Renoir/Lucienne or Phoenix HawkPoint1, native AMDGPU modeset,
  keyboard, touchpad, Wi-Fi, NVMe — remains open. See `STATUS.md`.

Note: the `user-mode-testbin` harness mounts no `/dev`, so device-file
end-to-end proofs run from the **boot-init shell** (`run-interactive` /
`musl-demo`), not the testbin.

---

## Current state (updated 2026-10-07)

Rungs 0-12 landed on `main` and are CI-proven; Rungs 13-14 landed behind
locally built rootfs images; Rung 15 is the open frontier. In short, NARF now:

- maps device memory into userspace (the Rung-0 `FileOps::mmap_frames` +
  `sys_mmap MAP_SHARED` keystone);
- exposes `/dev/fb0` (fbdev), `/dev/input/event*` (evdev), `/dev/uinput`, and
  `/dev/dri/card0` (DRM/KMS dumb buffers, page-flip events), each driven by a
  real musl C smoke;
- runs unmodified **libdrm** (`modetest` enumerates, sets a mode, presents,
  page-flips) and unmodified **libwayland** (a compositor serves multiple
  independent GUI client processes passing frame-backed buffers over
  `SCM_RIGHTS`), including an upstream weston client binary;
- boots **stock Fedora 43 with systemd as PID 1** — journal, D-Bus, udev with
  a populated database, seats, `systemd --user` — and runs **stock PipeWire +
  WirePlumber** to a complete audio graph on it;
- starts a **KDE Plasma Wayland session** on that image, which is where the
  work currently is.

A caveat that governs how to read all of this: the Fedora and Alpine images
are generated locally by `REGEN_*_rootfs.sh` and are **not committed**, so
Rungs 13-15 are marker-gated local gates, not automatic CI cases. Rungs 0-12
are automatic `musl-demo` cases.

The original pre-Rung-0 gaps once recorded here — "no device mmap",
"DUMB_BUFFER returns 0", "card wired to amdgpu" — are all resolved. Under
QEMU the card is the bochs/virtio-gpu DRM card; dumb buffers alloc, map and
scan out; `SETCRTC` blits.

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
- **dbus / udev / logind / fontconfig / freetype** as clients hit them.
  (Superseded: these are no longer shims — stock systemd, `systemd-udevd` and
  D-Bus run on the Fedora image. See Rung 13.)
- A minimal DE / panel. (Superseded: KDE Plasma is the target — Rung 15.
  This line read "GNOME/KDE remain out of scope" and is kept only to show
  where the scope moved.)

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
