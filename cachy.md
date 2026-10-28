# CachyOS Plasma on NARF — working notes

Last updated: 2026-09-08. Older dated sections below are kept for method notes,
but READ THIS TL;DR FIRST — it supersedes any earlier hypothesis it contradicts.

This file is a local handoff document. It is intentionally not part of the
repository history.

## ★★★★★★★★★★ EPOLL PARK-RECHECK LIVELOCK FIXED (2026-09-25) — boot now reaches kwin exec cleanly ★★★★★★★★★★

On current `origin/main` (15afcc91) the CachyOS boot hit a NEW gate before kwin
could even run: a 100%-CPU `epoll_wait` livelock that needed NO readiness wake to
sustain (all wake counters flat while the spin counter climbed). Root: the
own-stack park recheck `epoll_fd_has_ready` probed the LEVEL predicate
`poll_readiness() & POLL_IN`, which disagrees with `collect_ready`'s ET-aware
delivery for an EPOLLET fd whose edge was already consumed and for an
EPOLLEXCLUSIVE fd owned by another epoll — so the recheck said "ready, don't
park" while the re-executed `epoll_wait` delivered nothing → re-scan forever. It
pinned dbus-broker / systemd loops. FIXED: `epoll_fd_has_ready` now uses the
ET-aware `has_deliverable` oracle. Commit `59b30350`, branch
`fix/epoll-park-recheck-has-deliverable` (+ call-site regression test
`smoke_epoll_fd_has_ready_is_et_aware`). userspace/epoll ktest 2/2 green.

EPOLL RESULT (boot18/19/20): boot reaches `Reached target Graphical Interface`
→ Plasma Login Manager → `SESSION-EXEC kwin_wayland`, 15/16 CPUs idle — the epoll
gate is cleared. But kwin then did NOT present (no SETCRTC/PAGE_FLIP): the
software path was blocked at EGL_BAD_ALLOC → see the SECOND fix below.

## ★★★★★★★★★★ EGL_BAD_ALLOC = PRIME import gated to CARD nodes only — FIXED; DESKTOP RENDERS + LOGIN WORKS (2026-09-25) ★★★★★★★★★★

Root-caused by CODE REVIEW (kwin stderr is NOT on serial — it's a systemd USER
service, and system-journald ForwardToConsole does not forward user-session logs;
don't waste boots trying to capture it that way). `sys_ioctl` gated BOTH PRIME
ioctls on `ops.as_drm_card_index().is_some()` — a CARD-only check. kwin's llvmpipe
GBM/EGL context runs on the RENDER node (renderD128) and imports the scanout
dma-buf there via DRM_IOCTL_PRIME_FD_TO_HANDLE (0x2e) → the render-node fd
returned None → fell through → -EOPNOTSUPP → eglCreateImageKHR = EGL_BAD_ALLOC.
This is exactly the unmerged 120ffc74; the FileOps trait already had
`as_drm_render_index()` (impl on the render node) — sys_ioctl just never consulted
it. FIX (branch fix/drm-prime-import-render-node, cfd630bd): both PRIME gates
accept card OR render node. + regression tests in abi_drm_prime_tests.rs.

RESULT (boot22, both fixes = epoll 59b30350 + prime cfd630bd, GTK+virgl KVM 8 GiB):
LOGIN WORKS (user-confirmed on screen). Chain: greeter kwin → SETCRTC #1 → present
→ full Plasma session (kwin_wayland_wrapper --xwayland) → SETCRTC #2 → SUSTAINED
PAGE_FLIP/virtio-blit to 2048+ → `SESSION-EXEC plasmashell`. Zero teardown.

NEW BLOCKER (the desktop does NOT finish loading): once plasmashell exec's, ALL
16 CPUs peg at CPL=0 (kernel mode, NO userspace) for minutes — page flips freeze
at 2048, no teardown, no STALL-WD, no panic; window elapses "still loading". CPL=0
across all cores = an all-CPU KERNEL-side livelock (distinct from the single-task
epoll spin just fixed), the ONION-#3-class scheduler/wake busy-poll
([[project_io_wait_generation_busyspin]]). This is the next gate. See
[[project_plasmashell_all_cpu_kernel_spin]].

## ★★★★★★★★★★ GREETER TEARDOWN ROOT-CAUSE CHAIN (2026-09-08, cgevt_trace boot) ★★★★★★★★★★

Instrumented sys_exit_group (GEXIT probe, ungated, graphical comms) + booted with
kernel cmdline `cgevt_trace` (enables the existing SIGSEND / USEREXIT-killed-by-signal
probes in raise_signal_pending / terminate_current_task). Two clean boots
(scratchpad/run_gexit.log, run_sig.log) give the full chain:

1. kwin_wayland (greeter compositor, cg .../plasma-login-kwin_wayland.service) comes
   up FULLY: EGL, wayland-0 listener, OpenGL compositing, mode 1280x800, presents
   SETCRTC #1 + blit #1 (and sometimes a PAGE_FLIP). Loads ALL effects; last is
   "zoom".
2. Then kwin VOLUNTARILY exits — two kwin_wayland.re pids: one exit_group(-1)=255
   right after "loaded effect zoom" (SILENT, no kwin stderr, comm stayed
   kwin_wayland.re = a FORK that never exec'd), then the other exit_group(15) after
   "Removing output". NOT a signal (GEXIT is the exit_group *syscall* handler;
   terminate_current_task's killed_by_signal probe never fires for kwin), NOT a
   crash, NOT read-only home / ksycoca / locks / hotplug / DRM-master-steal.
3. With kwin gone, plasma-login-greeter (the greeter UI, cg .../plasma-login.service)
   can no longer reach the compositor: "Could not load the Qt platform plugin
   \"wayland\" in \"\" even though it was found" → falls back to "xcb" → also
   fails → Qt qFatal → SIGABRT, core_dumped=true (self-sent sig 6). THIS is the
   branch's namesake "greeter-qfatal".
4. plasmalogin-helper restarts startplasma-login-wayland → the whole cycle repeats
   (restart loop) → no stable login UI.

KEYSTONE = step 2: why does a fully-initialised pure compositor (argv has NO
--exit-with-session) voluntarily exit_group(-1) right after loading effects, with a
forked kwin_wayland.re child that exits -1 silently? Leading theory: kwin forks a
HELPER (GL/EGL probe? Xwayland pre-exec setup? a subprocess) that fails a NARF
syscall and _exit(-1)s before exec (so comm stays kwin_wayland.re, no stderr), and
main kwin treats that as fatal → exit(15). NEXT INSTRUMENT: trace the forked
helper's syscalls (what pid-with-exit(-1) does between clone and exit_group) — it
emits no userspace stderr, so only a kernel syscall trace on that tid will show it.

## ★★★★★★★★★ SOFTWARE SCANOUT WORKS — real blocker was read-only greeter HOME (2026-09-08) ★★★★★★★★★

The "software scanout / SET_SCANOUT no surface" theory was WRONG (stale from an
earlier session). Ground truth from scratchpad/run_gp.log (NARF systemd-pid1 boot):
the software (llvmpipe) present path is FULLY WORKING.
- kwin_wayland (greeter, user plasmalogin uid 957) comes up: EGL init OK, creates
  `/run/user/957/wayland-0`, "OpenGL compositing has been successfully initialized",
  detects output "Virtual-1-NARF Display", and hits
  `kwin_wayland_drm: Using legacy path to set mode 1280x800`.
- NARF then presents: `drm: SETCRTC #1 crtc=1 fb=1 1280x800 pitch=5120 backing=yes`
  → `drm: virtio blit #1 ... -> scanout 1280x800`, then `PAGE_FLIP #1/#2 backing=yes`
  → `virtio blit #2/#3`. So SETCRTC/PAGE_FLIP resolve dumb backing and blit to the
  virtio-gpu scanout (TRANSFER_TO_HOST_2D + RESOURCE_FLUSH). No SET_SCANOUT gap.

REAL blocker: the greeter's HOME `/var/lib/plasmalogin` is on the READ-ONLY ext4
distro root (NARF mounts it ro — ext4 write features unsupported). Smoking gun:
  `Failed to create /var/lib/plasmalogin/.cache/mesa_shader_cache ... (Read-only file system)`
Cascade: KConfig QLockFile fails on `~/.config/kwinrc.lock` (error 2 = PermissionError)
and `~/.local/state/*.lock` (error 3), ksycoca can't build → the greeter session
tears down ONE frame after first present: logind revokes evdev, kwin
"Removing output" and exits, plasmalogin respawns the greeter → a new instance hits
"Failed to create wl_display (Connection refused)" → restart loop, no stable login UI.
(The kglobalaccel "Not connected to D-Bus server" spam is a symptom of the churn,
not the cause — the session bus at /run/user/957/bus connects fine.)

FIX (this branch debug/cachyos-greeter-qfatal, frame/src/bare_main.rs, mnt-dev-bind
initcall): mount a world-writable (1777) tmpfs over `/var/lib/plasmalogin` AND
`/home` (guest paths, i.e. /mnt/... pre-chroot), mirroring the proven 9b99f14c
`/home` fix. NOTE: 9b99f14c (DISTRO_WRITABLE_RUNTIME_MOUNTS: /tmp,/var/tmp,/run,/home)
lives on the drm-master-arbitration branch and is NOT in this branch's history — so
this branch had NO writable-home overlay at all. systemd already provides /run and
/tmp here (wayland socket + plasmalogin auth socket both worked), so only the two
home trees are added. COMMITTED 826e21ba.

RESULT (scratchpad/run_home_fix.log): fix VERIFIED active + effective — both mounts
appear, ZERO EROFS, ZERO KConfig-lock failures (down from many), and ksycoca now
BUILDS ("kf.service.sycoca: Recreating ksycoca file ... version 307"). BUT the
greeter STILL tears down ~2 frames in, so the read-only home was a real bug but NOT
the teardown cause. Corrected causal chain: kwin comes up fully (EGL, wayland-0
listener, OpenGL compositing, mode 1280x800, presents SETCRTC #1 + PAGE_FLIP #1/#2 →
virtio blit #1/#2/#3), loads ALL effects, then EXITS CLEANLY (unloads every
kwin/Qt plugin .so; zero kwin scheduler entries after; no signal, no crash, no
DRM-master steal, no stated reason). Only AFTER kwin's wayland-0 listener is gone do
the greeter UI clients connect → WLREFUSED (same_path_listener_exists=false) →
"Failed to create wl_display (Connection refused)". So it's a LIFECYCLE RACE: kwin
self-quits before its UI client connects. kwin argv has NO --exit-with-session
(`kwin_wayland.real --no-lockscreen --no-global-shortcuts --no-lock-activities
--inputmethod plasma-keyboard --locale1`), so why a pure compositor self-quits is
the open question. Ruled out: read-only home (fixed), ksycoca (builds now),
kglobalaccel D-Bus (non-fatal), locks (fcntl always-on, 0 failures, no task blocks
on flock), shared-connection/listener-lookup bug (kwin genuinely exited). NEXT:
GEXIT probe added to sys_exit_group (logs kwin's exit_group code) — a clean 0 =
intentional/session-driven quit; non-0 = fatal error. Also scrubbed stale
linux-compat feature-gate comments (02c8f838).

## ★★★★★★★★ HARDWARE GL *IS* ACHIEVABLE via classic VirGL (2026-09-08, agent) — earlier "ruled out" was WRONG ★★★★★★★★

A worktree agent PROVED hardware GL works on THIS exact host+guest+QEMU, refuting
the "HARDWARE-GL RULED OUT" section below. Evidence in scratchpad/:
- Booted the CachyOS image under REAL LINUX (its kernel, init=/bin/bash,
  `-device virtio-gpu-gl-pci` NO drm_native_context, `-display egl-headless`),
  ran eglinfo → `renderer: virgl (AMD Radeon 780M ... radeonsi phoenix)`,
  **OpenGL 4.3 / GLES 3.2**. Kernel: `+virgl +context_init +edid -resource_blob
  -host_visible`, capsets {1,2} only. NO blob / host-visible / native context
  needed. (boot1b_no_nctx.log)
- Host is newer than cachy.md recorded: virglrenderer 1.3.0 (soname .1.11.0, built
  WITH amdgpu drm native-context) + QEMU 11.1.1 (has virtio-gpu-gl
  `drm_native_context=` prop). With that flag the host DOES offer capset 6 — but
  the GUEST Mesa 26.2.1-arch was built WITHOUT the amd-virtio backend (no amdvgpu
  symbols), so capset-6 native context is a DEAD END unless the image's Mesa is
  rebuilt (-Damd-virtio). DO NOT set drm_native_context=on.
- Classic virgl IS compiled into this guest Mesa (VIRGL_DEBUG/virgl_shader_sync
  symbols). So my "native-context-only, no classic fallback" reading was WRONG —
  the reason NARF drops to llvmpipe is NARF-side virgl-3D gaps, not Mesa.

WORKING ioctl sequence (real-Linux reference, scratchpad/trace_novnctx.log):
DRM_VERSION → GET_CAPS(may EINVAL, Mesa CONTINUES) → 7× GETPARAM → CONTEXT_INIT →
GET_CAPS(capset 2) → core GET_CAP → RESOURCE_CREATE(56B, guest-backed) →
EXECBUFFER+WAIT render loop. Guest-backed resources suffice.

NARF gaps to close for classic VirGL (drivers/gpu + drivers/virtio/gpu_pci.rs):
1. GETPARAM CAPSET_QUERY_FIX (param 2) returns 0 → should be 1 (selects capset 2).
2. Feature negotiation ACKs only F_VIRGL (bit 0) → also negotiate F_CONTEXT_INIT
   (bit 4) and F_EDID (bit 1).
3. CONTEXT_INIT (ensure_virgl_context) ignores capset_id → must bind capset 2.
4. Missing VIRTGPU_WAIT (nr 0x48) and TRANSFER_FROM_HOST_3D (nr 0x46) — Mesa's
   render loop calls WAIT every frame; NARF returns ENOTTY. (Synchronous
   transport ⇒ WAIT can return 0/idle.)
5. Then wire the virgl-rendered resource to scanout (SET_SCANOUT).
Ioctl sizes that already match: RESOURCE_CREATE(56), GETPARAM(16), GET_CAPS(24),
CONTEXT_INIT(16), EXECBUFFER(64). Driver name "virtio_gpu" correct.
NEXT: add a trace at top of dispatch_virtgpu_render, diff NARF's live sequence vs
trace_novnctx.log, close the gaps. This SUPERSEDES the software-llvmpipe path as
the primary route (the PRIME-import fix 120ffc74 stays — correct either way).

## ★★★★★★★ EGL_BAD_ALLOC FIXED (2026-09-08) — PRIME import on render nodes; kwin now MODESETS ★★★★★★★

Committed 120ffc74. Root cause found by tracing every render/card-node ioctl
(RNODE-IOCTL/CNODE-IOCTL): kwin's software (llvmpipe) EGL/GBM context is on the
RENDER node (renderD128); it creates a dumb scanout buffer on card0, exports it
as a dma-buf, and imports the fd on renderD128 via DRM_IOCTL_PRIME_FD_TO_HANDLE
(nr 0x2e). But sys_ioctl only serviced the PRIME ioctls when
`ops.as_drm_card_index()` was Some — render nodes returned None, so
PRIME_FD_TO_HANDLE fell through to the driver dispatch → -EOPNOTSUPP →
eglCreateImageKHR(EGL_LINUX_DMA_BUF_EXT) = EGL_BAD_ALLOC. Fix: added
`FileOps::as_drm_render_index()` (impl on DriRenderFile), and accept it in both
PRIME gates in sys_ioctl (the import handler is node-independent — resolves the
dma-buf's as_prime_gem_handle).

VERIFIED: EGLImageKHR-err 1→0, PRIME_FD_TO_HANDLE on renderD128 now ok, and kwin
advances past the EGLImage step through "OpenGL compositing initialized" →
"Using legacy path to set mode 1280x800" → effect loading. Never reached modeset
before. So kwin is now on the software (llvmpipe) compositing path and modesetting.

TWO REMAINING blockers (both unrelated to the PRIME fix):
1. **QMP screendump still "no surface"** — even alive+modeset, kwin hasn't attached
   a scanout resource to the virtio-gpu. The legacy SETCRTC/pageflip path isn't
   wiring the framebuffer to the virtio-gpu scanout (VIRTIO_GPU_CMD_SET_SCANOUT)
   for kwin's dumb buffer, OR kwin is torn down before its first present.
2. **Session teardown** — systemd-logind revokes the greeter session's evdev
   devices (~50s in; the kglobalaccel D-Bus "Not connected" cascade) → kwin
   "Removing output" → exits. Same teardown seen throughout; now the thing
   between kwin-modesets and a visible login screen.

Note: hardware GL stays ruled out (below) — this is the SOFTWARE path, which is
the tractable route. Commits so far: mmap batch, EDID, capset-enum (2ec4849c),
PRIME-import (120ffc74).

## ~~HARDWARE-GL RULED OUT~~ — SUPERSEDED/REFUTED (see agent finding above; classic VirGL works)

Full VIRTGPU-ioctl trace (VGPU-TRACE in dispatch_virtgpu_render) settles it.
Per Mesa init, on the render node it issues: VERSION(x12), GET_CAP, then
GETPARAM 1..7 and GET_CAPS(id=6 only), then STOPS — never GET_CAPS(id=2), never
CONTEXT_INIT / RESOURCE_CREATE_3D / EXECBUFFER. GETPARAM values NARF returns:
1(3D_FEATURES)=1, 2=0, 3(RESOURCE_BLOB)=0, 4(HOST_VISIBLE)=0, 5=0,
6(CONTEXT_INIT)=1, 7(SUPPORTED_CAPSET_IDs)=0x6 (capsets 1,2).

Levers TRIED, none made Mesa request capset 2 or reach CONTEXT_INIT (all reverted):
EINVAL on GET_CAPS(6); mask=0x6 (bit 6 clear); RESOURCE_BLOB=1. Mesa probes
capset 6 UNCONDITIONALLY and, absent it, falls to llvmpipe — it has NO
classic-VirGL (capset 2) fallback for this device. The host virglrenderer 1.11
enumerates only capsets 1,2 (NOT 6), so native context is unavailable host-side.

CONCLUSION: hardware GL (virgl) is UNREACHABLE from the NARF side with this
Mesa+host. Completing NARF's virgl-3D command path (CTX_CREATE/RESOURCE_CREATE_3D/
SUBMIT_3D) is MOOT — Mesa will never call those ioctls. The only NARF-tractable
route to pixels is the SOFTWARE path: kwin already runs on llvmpipe; the block is
`eglCreateImageKHR(EGL_LINUX_DMA_BUF_EXT)` → EGL_BAD_ALLOC, i.e. NARF's DRM
GBM/PRIME/dmabuf-import path for a software (kms_swrast) client. Fix that and kwin
renders in software (slow but visible). Alternatives are host-side (older Mesa
with classic-virgl fallback, or a virglrenderer built with drm renderers to offer
capset 6). The committed capset layer (2ec4849c) stays — it is correct/Linux-
faithful and is what keeps GET_CAPS/params honest for any future path.

## ★★★★★ CURRENT STATE (2026-09-08) — kwin now RENDERS via GL until EGL_BAD_ALLOC; the wall is Mesa native-context vs host virgl ★★★★★

Branch `debug/cachyos-greeter-qfatal`, rebased on origin/main (7a0d8fef).
Two fixes landed that DID move the needle; the old journald/write(fd=2) theory
below is SUPERSEDED (see "Corrections").

COMMITTED:
- `mmap: batch file-backed MAP_PRIVATE reads` (dedup on rebase). Eager file-mmap
  read one 4 KiB page per `ops.read` (~41k round-trips for a 161 MiB DSO). Now
  256 KiB batches. THIS made kwin start fast enough to run at all (was: never
  finished loading Qt plugins in 720 s). See also mmap-eager memory note.
- `drm: expose a synthetic EDID blob on synthesised connectors`. Connectors
  reported count_props=0, no "EDID" blob; kwin logged "Could not find edid" and
  built no output. Added drivers/gpu/src/drm/edid_gen.rs + EDID prop in
  GETCONNECTOR/OBJ_GETPROPERTIES/GETPROPERTY + a GETPROPBLOB handler (0xAC).
  Now kwin reads it → output "Virtual-1-NARF Display" → reaches OpenGL.

VERIFIED PROGRESSION (GTK+VirGL boot, KVM -cpu host, SMP=4, 8 GiB):
kwin starts → listens on wayland-0 at ~22 s → greeter QML connects & runs →
kwin loads effects/decorations → `kwin_scene_opengl: Created EGL context` →
`OpenGL compositing successfully initialized` → **`Error creating EGLImageKHR
"EGL_BAD_ALLOC"`** → `Removing output` → teardown. QMP screendump = "no surface".

★ EGL_BAD_ALLOC ROOT CAUSE (instrumented the VIRTGPU ioctls): Mesa runs
**llvmpipe (software)**, not VirGL — its dmabuf→EGLImage import is what throws
EGL_BAD_ALLOC. Why llvmpipe:
- VirGL IS negotiated (host_offers_virgl=true, virgl_enabled=true; host has
  libvirglrenderer 1.11, QEMU virtio-gpu-gl gl=on virgl=on 3d=on).
- Host enumerates ONLY capset 1 (VIRGL) and 2 (VIRGL2, max_size 1408) — NOT
  capset 6. NARF's GET_CAPSET forwarding is fine (capset 2 returns 319 nonzero
  bytes).
- This CachyOS Mesa's `virtio_gpu` driver is **native-context-only**: it probes
  ONLY capset 6 (DRM native context), never capset 2, and does NOT fall back to
  classic VirGL. Capset 6 needs RESOURCE_BLOB + a virglrenderer built with drm
  renderers — the host offers none → Mesa drops to llvmpipe.

★ CAPSET-ENUMERATION LAYER (COMMITTED 2ec4849c, correct but INSUFFICIENT): drivers/virtio/src/gpu_pci{,/cmd}.rs + drm_ioctl_bridge.rs.
Reads capsets via GET_CAPSET_INFO at bring-up (iterate index until non-OK),
stores {id,max_ver,max_size}; DRM GET_CAPS validates against it (EINVAL for a
capset the host didn't enumerate, Linux-faithful); GETPARAM
VIRTGPU_PARAM_SUPPORTED_CAPSET_IDs (param 7) returns the real mask (=0x6).
RESULT: all correct — but Mesa STILL probes only capset 6, ignores the 0x6 mask,
never requests capset 2, still uses llvmpipe. Confirms Mesa won't touch classic
VirGL regardless of NARF. So the layer is correct infrastructure, not a fix.

★ TRIED & FAILED — force classic VirGL via `GALLIUM_DRIVER=virpipe`: DUD.
`virpipe` is Mesa's *vtest* driver (talks to an external `virgl_test_server`
over a socket, absent in the guest) → `lost connection to rendering server on 8
read -1 22` (EINVAL), kwin never reaches GL. It does NOT test classic-virgl-over-
virtio. The two lines added to the image's /etc/environment
(GALLIUM_DRIVER=virpipe, MESA_LOADER_DRIVER_OVERRIDE=virpipe, via `udisksctl`
loop mount — host sudo is NOT "narf", user ran the sudo edit) now BREAK GL and
SHOULD BE REMOVED. There is no simple env to force classic-virgl-over-virtio:
the `virtio_gpu` gallium driver IS classic virgl by default, yet this Mesa
probes ONLY capset 6 and never requests capset 2 — so either classic-virgl
fallback is absent in this Mesa build, or NARF's virgl 3D command path
(CTX_CREATE/RESOURCE_CREATE_3D/SUBMIT_3D) is incomplete enough that it is never
attempted. Undetermined; needs Mesa debug (EGL_LOG_LEVEL=debug / MESA_DEBUG=1
in /etc/environment) to see the driver-selection reasoning.

★ Corrections to earlier TL;DRs:
- journald is NOT stalled: its park census cycles sysnr 232/288/0
  (epoll_wait/accept4/read-kmsg) = a healthy event loop. The "kwin blocked in
  write(fd=2) to the journal socket" theory was pre-mmap-fix; once kwin could
  start, fd=2 is a regular File in the greeter, and kwin progresses to GL.
- The blank screen is the GL/scanout path (EGL_BAD_ALLOC), not an accept-wake.

★ OTHER OPEN NARF GAPS seen during teardown (self-contained, not the blocker):
EVIOCREVOKE returns EFAULT ("Failed to revoke evdev device: Bad address");
VT restore ENOTSUP.

★ VERIFICATION HAZARD: an intermittent EARLY-BOOT HANG (~4 s guest, stalls at
systemd-journald/modprobe/udevadm, guest goes silent, QEMU exits on its own) hit
~7 times in a row this session and repeatedly wasted boots. NOT caused by the GPU
changes (virtio-gpu probe completes before it). Retry the boot to get past it.


## ★★★★ DEEPEST ROOT (2026-09-07) — kwin blocks in write(fd=2) to the undrained journal socket ★★★★

Probe added (UserTaskCtx.dbg_syscall_nr/rip/arg0, recorded at syscall entry,
printed in PARKREP). kwin's uncategorized park is `sysnr=1 rip=0x409003d109a0
arg0=2` = **blocked in `write(fd=2)`** (stderr). kwin's stderr is the systemd
journal stream socket `/run/systemd/journal/stdout`, and that socket is NOT being
drained: `UNIXPEND name=/run/systemd/journal/stdout n=16 owner_tid=15 pid=1 parked
epfd_enc=5` — 16 pending connections, owned by PID1, never accepted (climbs 13→16).
kwin's log write fills the buffer → `write(2)` blocks forever.

FULL CHAIN (deepest first):
1. ROOT: the journal stdout socket-activation listener has a lost epoll
   accept-wake / accept-strand — journald never drains its pending connections
   (same class as the older EPOLLET/greeter fix + the unix accept-wake bugs).
2. kwin stderr(fd2) → that socket → buffer full → `write(2)` blocks.
3. kwin stalls ~6ms in, never registers `org.kde.KWin`.
4. `systemd --user` SIGTERMs kwin (Type=dbus not ready / target `BindsTo` cascade)
   ~9.5s later.
5. greeter can't connect to the dead compositor → qFatal → black screen.

THE FIX (next): make a pending connection on an AF_UNIX socket-activation listener
wake the parked acceptor (PID1's/journald's epoll on /run/systemd/journal/stdout),
so the journal drains and kwin's stderr write completes. Epoll-accept-wake /
EPOLLET-rearm class — NOT memory/graphics.

---

## ★★★ ROOT CAUSE (2026-09-07, later) — the greeter is a VICTIM; kwin is stopped ★★★

The KDE-greeter abort is NOT memory/graphics. Captured the greeter qFatal via the
PLSENDMSG probe (re-gated to unix-latency-trace): `Failed to create wl_display
(Connection refused)` → xcb fallback fails → `could not connect to display` →
qFatal. The greeter is a DOWNSTREAM VICTIM — the compositor is gone:
`SIGSEND sig=15 -> pid=8 kwin_wayland  cg=.../plasma-login-kwin_wayland.service
FROM pid=13 comm=systemd`, then `USEREXIT pid=8 kwin killed_by_signal=15`. The
user `systemd --user` SIGTERMs kwin; the greeter (execs AFTER) can't connect.

WHY systemd stops kwin: kwin starts (~ms120700), PARKS almost immediately —
`scans=0 checks=20`, ALL wait fields ZERO (uncategorized blocking syscall), only
~6ms user CPU — never registers `org.kde.KWin`; systemd SIGTERMs it ~9.5s later
(NOT the 90s start-timeout). `plasma-login-kwin_wayland.service` is Type=dbus
(BusName=org.kde.KWin); `plasma-login-wayland.target` `BindsTo=` both kwin and the
greeter, so a readiness failure cascades to tear kwin down. ROOT = kwin blocks in
an early uncategorized syscall and never becomes ready.

NO-TRACE BASELINE (run20, `--features cgroup` only): reaches
`systemd-logind: New session c1 class greeter`; QMP screendump vgpu0 = 1280x800,
99% black + a 32x32 RGBW GPU power-on square (no compositor surface). IDENTICAL to
traced runs ⟹ observer effect RULED OUT.

NEXT: identify WHICH syscall kwin blocks on. Add a targeted probe that, when a
`kwin` task parks with all wait fields 0, prints its user RIP + in-flight syscall
number (symbolize offline); or trace_comm=kwin (slow). Old-note suspects: kwin
blocks right after creating its udev/DRM netlink monitor, or on the session bus /
logind TakeDevice / DRM master. Now a systemd-user + kwin-startup issue.
Branch: `debug/cachyos-greeter-qfatal` (off origin/main after PR #287 merged the
migration + path-parity + rseq fixes + VT/sys_read). Diagnostics uncommitted, all
feature-gated OFF; PLSENDMSG/PLWRITE re-gated to also fire under unix-latency-trace.

---

## ★ CURRENT STATE (2026-09-07) — read this first ★

Continuing the SMP greeter-abort hunt on branch `feat/vt-layer-seat0`
(rebased on origin/main). New this session:

LANDED (commit `754c92b0`, branch feat/vt-layer-seat0): **page migration
flushed every CPU AFTER copying, not before.** `relocate_leaf` /
`migrate_page_to_node` / `migrate_huge_page_to_node` copied the source frame
into the destination and only then unmapped + broadcast-invalidated the old
leaf, and `flush_region_broadcast` even *skips* the cross-CPU shootdown for a
non-`vm_shared` AS — but the migrator (compaction / `migrate_pages(2)`) runs
from a FOREIGN task, so a single-threaded victim resident on another CPU kept
translating to a frame already returned to the buddy allocator (cross-process
physical UAF), and a store racing the copy was lost (torn write → heap
garbage). Fixed to Linux order: unmap+flush-everywhere → copy → install; the
broadcast is now unconditional. New regression test
`smoke_migrate_frame_flushes_before_copy` (hook shim plays a racing writer);
all 8 memory/migrate kernel tests green. **This is a real latent SMP
memory-safety bug but is NOT proven to be the greeter corruptor** — it needs
memory pressure (compaction) or automatic NUMA balancing to fire, and the
greeter boot has 7 GiB free, so migration is almost certainly not running.

EFAULT ROOT-CHARACTERIZED (runs 2–3, `feat/vt-layer-seat0`): the burst of
`newfstatat`/`openat` = EFAULT on kwin heap pointers in the `0x1000043…` range
is **stable physical corruption of a PRIVATE anonymous heap page**, not a
translation bug:
- The faulting VA is in a `RegionPerms(0x4006)` = WRITE|READ|BRK_HEAP region
  based at `0x100000000000` (the malloc/mmap heap), NOT a shared/file mapping.
- `expected_phys == live_phys`, `root_matches=true`, and a forced `invlpg`
  re-read returns the SAME bytes → the frame genuinely holds garbage; it is not
  a stale/lost TLB entry or wrong-CR3.
- The buffer holds a correct prefix `/etc/fonts/conf.d/` + one char, then
  high-entropy binary garbage (`7d 72 38 85 c9 e0 …`); `nul_at≈78`,
  `utf8_ok=false`. `copy_user_cstr_checked` maps the non-UTF-8 to EFAULT — the
  EFAULT is *downstream* of the corruption.
- Greeter (`plasma-login-greeter`) + wallpaper both SIGABRT (signal 6,
  core_dumped) at the SAME instant, in `QMessageLogger::fatal` (symbolized
  abort stack: `pthread_kill`→`raise`→`abort`→Qt qFatal). kwin exits 15/-1 and
  systemd restart-loops the service → black screen. (`SuccessExitStatus=15`
  confirms 15 is a *stop*, so the -1/255 is the real internal failure.)

RULED OUT this session: TLB/translation (invlpg re-read identical); the new
migration path (no memory pressure); the demand-fault path (`claim/finish_
demand_page` ticket table serializes concurrent same-page faults correctly);
the TLB-shootdown IPI machinery (`shoot_request_mask` ack-waits every target;
`defer_idle_targets` rechecks the idle mask after publishing debt). COW-split
double-free was checked and is correct (`free_frame` = `cow::dec_ref`, only the
1→0 transition returns to buddy).

DIAGNOSTIC BLOCKER (recurrent observer effect): at SMP=16 the
`unix-latency-trace` PARKREP/UNIXPEND/census console flood makes PID1 stall
spinning in `narf_console::write_str` on the console `IrqSafeSpinLock`
(symbolized: rip `narf_console::write_str+0x1a2`, contended lock past
`__text_end`) → RCU stall → STALL-WD, *before* kwin starts (~2300 lines).
Intermittent: runs 1–3 reached kwin, runs 4–5 stalled here. The console-based
probes are self-defeating at 16 CPUs. NEXT: either retry for a lucky boot, drop
to `NARF_QEMU_SMP=4` (less console pressure, may still repro), or move the
ownership audit off the console (fixed memory slot / dump-once).

OWNERSHIP AUDIT DONE (runs 7 & 10, SMP=4 — SMP=4 reproduces the corruption AND
avoids the SMP=16 console-flood stall, so it is the working repro). The EFAULT
probe (`compat.inc.rs::trace_first_kwin_path_efault`) dumps
`cow::count`+`rmap::owner_count`+owner roots+`file_cache` for the corrupted
frame. Result, identical across runs:
```
frame 0x24d3db000 @va 0x10000428ce30: cow_refs=0 rmap_owners=1 file_cache=None
  owner[0] root=<live_cr3> va=... foreign=false
```
So the corrupted frame is, by EVERY NARF bookkeeping structure, exclusively
kwin's own anonymous heap: sole rmap owner = kwin's own AS, cow_refs=0, NOT in
the shared-file page cache. REFUTED this session, with direct evidence:
COW/double-ownership, cross-AS sharing, fork, page-migration, AND page-cache↔anon
frame aliasing. And the garbage bytes (`7d 72 38 85 c9 e0 fa d3 …` after
`/etc/fonts/conf.d/`) are **byte-identical across every run and every SMP count**
— deterministic content, not race noise.

CONCLUSION / new leading theory: this is a **lost store to established private
user memory** under SMP. kwin `snprintf`s `/etc/fonts/conf.d/<name>` into a heap
buffer; the prefix sticks but the `<name>` tail does not — the frame keeps its
prior (deterministic) content there. Not an aliasing/ownership bug (all refuted);
either (a) a genuinely lost/torn store to a sole-owned anon page under SMP
(cache/TLB/ordering), or (b) kwin-internal glibc heap corruption seeded by an
EARLIER NARF syscall that returned wrong bytes into a heap buffer (a read/recv
scatter to the wrong offset), so the "path pointer" already aims at stale data.
POISON-FILL PROBE DONE (runs 11 & 12, feature `poison-anon-demand`, gated fill in
`AddressSpace::fill_fresh_anon_frame`; pattern `0xA11C_0DED_A11C_0DED`):
- run11 (poison ALL fresh anon frames): broke at `syscalls=21` — the FIRST
  userspace process read a should-be-zero page and faulted. Full poison is
  infeasible (violates the MAP_ANONYMOUS/`calloc`/BSS zero-page guarantee).
- run12 (poison gated to kwin/plasma comms via `set_poison_anon_gate`): reached
  the plasma-login stack but `plasmalogin` (pid 23) took a `#GP` at
  `rip=faultva=0x40000000b36e` with `rax=0xA11C_0DED_A11C_0DED` — it transferred
  control through a poison value read from a should-be-NULL calloc slot, BEFORE
  kwin started. Inherent: Plasma/Qt processes rely on zero pages, so any poison
  crashes them before the fontconfig path is built. The probe cannot read out the
  fontconfig buffer directly.

CONCLUSION (poison result + all non-poison runs): the corruption is a LOST STORE
to ESTABLISHED private memory, NOT a fresh-page/demand-zero bug. Proof: the anon
demand path ALWAYS zero-fills a genuinely fresh page, so a fresh page with a lost
tail-store would read back ZERO in the tail; every non-poison run instead shows
NON-ZERO deterministic data there. So kwin/fontconfig wrote the filename tail and
the store did not stick, leaving prior content. With `cow_refs=0` + sole rmap
owner + `file_cache=None`, the leading root is a stale TLB entry on the writing
CPU after a frame-changing op (COW split / remap — `cow_refs=0` also fits a
post-COW-split private copy), or a memory-ordering gap — all aliasing/migration/
page-cache/fresh-page theories are REFUTED with direct evidence.

FLUSH BISECT DONE — NEGATIVE (runs 13–15, feature `force-remap-broadcast` +
`set_remap_broadcast_gate` comm-gated to kwin/plasma so the fork storm keeps the
cheap path). Forcing every kwin COW-break `remap_page` to an unconditional
all-CPU broadcast of BOTH the torn-down and freshly-installed leaf did NOT change
the corruption (run15 reached kwin, `KWINEFAULT=2`, identical
`/etc/fonts/conf.d/V`+`7d7238…` garbage, same sole-owned frame). ⟹ the
COW-break/remap TLB-flush path is EXONERATED — as expected: kwin is `vm_shared`
so `remap_page` already broadcasts the unmap unfiltered+ack-waited, and x86 never
caches not-present entries so the new-leaf broadcast is a no-op. (`unmap_4kb`/
`invlpg_global` go through the shootdown HOOK → `shoot_range_mask(u64::MAX)`,
which is unfiltered by residency/idle-defer, unlike `tlb_shootdown::dispatch_
remote`.)

REFRAME — likely a DIRECTORY-READ (getdents) or file-read bug, NOT memory. The
real `/etc/fonts/conf.d` (checked via debugfs on the image) contains only normal
`.conf` symlinks — `51-local.conf`, `10-hinting-slight.conf`, … — NONE starting
with `V`/binary. fontconfig scans conf.d via scandir→getdents and builds
`<dir>/<name>`. kwin got `/etc/fonts/conf.d/` + a name that is binary garbage
(`56 7d 72 38 85 c9 e0 fa d3 3e a1 ec 06 44 …`, deterministic across every run).
So NARF's getdents on this ext4 dir (or a read of fonts.conf) delivered a wrong
dirent NAME into kwin's buffer. This explains EVERYTHING the memory theories
could not: determinism (same dir → same wrong bytes), the intact prefix (kwin's
snprintf `%s/`), the correct memory bookkeeping (sole-owned anon frame, right
translation, right flush — because the bytes were WRITTEN there by a syscall, not
lost/aliased). SMP-only per old notes ⟹ suspect a multi-block ext4 directory read
that races/tears under SMP, deterministically.
GETDENTS/EXT2 AUDIT DONE — NEGATIVE, and the path is EXCLUDED as the source.
Traced `read_all_inode_bytes`→`read_inode_at` (block-by-block, correct multi-block
math) → `read_block` (per-volume physically-keyed PageCache, correct
double-checked fill under `fill_lock`; `page_cache.clear()` only on the write
path, which never runs read-only) → `read_byte_range`→`device_read_into` (DMA
scratch from a POOL with exclusive ownership held across `submit().await` — no
shared-scratch tear; correct multi-block staging loop) → `for_each_entry`/
`parse_entry` (bounds-checked rec_len walk). No multi-block SMP tear exists. The
PageCache is per-volume (own map), so the hardcoded `fs_id:0/inode:0` key is a
safe single-volume namespace, not a cross-volume alias.
DECISIVE: `walk_dir` (feeds `enumerate_async`→getdents) does
`str::from_utf8(entry.name)` and SKIPS non-UTF-8 names. The garbage
`56 7d 72 38 85 …` has `0x85` (invalid UTF-8 lead) ⟹ it would be FILTERED and
never returned to kwin. So the directory read CANNOT be the source of this
symptom.

⟹ RE-REFRAME: kwin got a VALID name from getdents (e.g. `51-local.conf`), wrote
`/etc/fonts/conf.d/51-local.conf` into its heap buffer, and the filename TAIL was
then overwritten with non-UTF-8 binary — a corruption of kwin's ESTABLISHED heap
AFTER the write. Matches the ownership finding (sole-owned anon frame, right
translation, right flush) and the negative flush bisect. Leading mechanism now:
a WRONG-DESTINATION `copy_to_user` — a syscall (file `read`/`pread`, `recvmsg`,
etc.) writing real data into the wrong heap offset (that path does NOT filter
content, explaining the deterministic real-data-looking payload).
read/pread/readv copy_to_user destination math AUDITED — clean (per-call local
staging buffer, monotonic `ptr+total` / `iovec.base+iov_offset` destinations,
`position_lock`-guarded file offset; no shared buffer → no SMP dest bug).

★★ THE EFAULT WAS NON-CAUSAL — the whole fontconfig/corruption line is a red
herring (run17, decisive). ★★ Committed the real Linux-parity fix `6a2ce6a6`:
`copy_user_cstr_checked` returned EFAULT for a READABLE non-UTF-8 path; Linux
treats paths as opaque bytes and resolves → ENOENT. After the fix, run17 reached
kwin with **KWINEFAULT=0** (the EFAULT is gone) — BUT kwin still exits 15/-1 and
the greeter still aborts at the IDENTICAL `ABORTSTK rip=0x4090028812eb`. So the
fontconfig EFAULT never caused the abort; the greeter dies for a SEPARATE
upstream reason. Everything this session chased on the memory/corruption side is
exonerated as the abort cause (the fix is still correct and worth keeping).

NEXT (the actual open question): capture WHY the greeter qFatals. Abort stack =
pthread_kill→raise→abort→`QMessageLogger::fatal`; the qFatal MESSAGE goes to the
journal via sendmsg (binary — prior attempts to capture it failed). Options:
PLSENDMSG probe (sys_socket_sendmsg, gated syscall-trace) to grab journal
`MESSAGE=` fields at the greeter's death; QT_FORCE_STDERR_LOGGING + PLWRITE/
PLWRITEV fd-2 probes; or the kwin_capture.sh wrapper's kwin_err.log. kwin exits
15/-1 (self, not signalled) → likely `--exit-with-session` propagating the
greeter's failure.
Diagnostic infra left in tree (all feature-gated OFF): `poison-anon-demand`,
`force-remap-broadcast`, EFAULT ownership+file_cache probe, ABORTSTK/USEREXIT/
PLWRITE probes.

Independently-landable side bug found: `copy_user_cstr_checked` rejects any
non-UTF-8 path with EFAULT (`String::from_utf8(..).map_err(|_| EFAULT)`), but
Linux paths are byte strings — a valid Latin-1/non-UTF-8 filename should open,
not EFAULT. (Not the greeter cure — here the bytes are genuine corruption — but
a real ABI-parity bug; fixing it would only mask this symptom.)

## ★ CURRENT STATE (2026-09-04, updated) — read this first ★

UPDATE (post-rebase verification, corrected payload probes): `origin/main`'s
`/dev/kmsg` EOF fix is working in the real boot: systemd-journald starts, drains
kernel messages, and remains alive through Graphical Interface. The two local
VT/nonblocking-read commits also still reach the Plasma login session on 16 CPUs.
There is still no stable desktop.

The latest captures materially change the failure boundary:

- The old `NARF_QEMU_SMP=1` workaround is NO LONGER usable on this rebased
  tree/image. A clean GTK/virgl SMP=1 boot reaches the greeter session and
  execs both `kwin_wayland` and `kwin_wayland.real`, but QMP reports
  `screendump ... device=vgpu0` as `no surface`; the GTK window remains the
  framebuffer boot console. Do not promise an interactive login from SMP=1.
- KWin successfully initializes EGL 1.5/OpenGL compositing, opens
  `/dev/dri/card0`, discovers `Virtual-1`, and starts the compositor. Early
  EGL/virgl/DRM initialization is NOT the blocker.
- The user `dbus-broker` does NOT die. It remains live and routes systemd-user
  traffic after KWin teardown. KWin is exec'd with the correct
  `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/957/bus` and
  `XDG_RUNTIME_DIR=/run/user/957`.
- KWin's `QDBusError(...Disconnected...)` from KGlobalAccel is not evidence that
  the session broker dropped: `plasma-login-kwin_wayland.service` explicitly
  starts KWin with `--no-global-shortcuts`. The only live QDBus worker KWin needs
  in this mode connects successfully to the SYSTEM bus for logind. Do NOT chase
  the session broker/global-accelerator messages as the root.
- KWin then tears down and exits with status 15. Only afterward do the
  greeter/wallpaper attempts report `wl_display: Connection refused` and abort;
  those messages are downstream of the compositor going away.
- The strongest unexplained kernel-facing anomaly immediately before teardown is
  a burst of `newfstatat`/`openat` returning `EFAULT` for several ordinary-looking
  KWin heap pointers in the `0x100004...` range. An SMP=1 run was previously
  stable, so a lost/corrupted user mapping remains plausible. The repeated Mesa
  shader-cache `openat(...O_CREAT...) = EIO` and unsupported `O_TMPFILE = ENOTSUP`
  are real filesystem parity bugs, but KWin continues well past them.

NEXT: use the existing LIGHT `USEREXIT`/`SIGSEND` probes (not the D-Bus packet
firehose) to establish exactly who initiates KWin's status-15 shutdown, while a
targeted EFAULT diagnostic dumps the VMA/PTE ownership for the first bad
`newfstatat` pointer. Compare the same probe with `NARF_QEMU_SMP=1`; first-bad
EFAULT on SMP=16 but not SMP=1 is the clean discriminator. Corrected raw payload
capture is now in `sys_write`, `sys_writev`, and `sys_socket_sendmsg`: these
buffers are length-delimited and must use `copy_from_user_vec`, not
`copy_user_cstr` (the old probe silently discarded every non-NUL payload).

Saved host captures from this update: `/tmp/cachy_kwin_payload2.log`,
`/tmp/cachy_session_bus.log`, `/tmp/cachy_kwin_bus_connect.log`, and
`/tmp/cachy_kwin_env.log`.

UPDATE (run19, dumb-buffer lifecycle probes): the greeter aborted at ~48 s with ZERO
DUMBFREE/DUMBEXPORT/DUMBMMAP events — NO dumb-buffer activity at all before the abort.
⟹ the DRM dumb-buffer/PRIME free-while-mapped bug (both agents' #1) is REFUTED as the
cause: the greeter has llvmpipe threads (a GL context) but aborts BEFORE ever allocating
a scanout/PRIME buffer (consistent with "never presents"). Confirmed BEFORE the refactor,
which saved it. The DRM lifetime gap is still a real Linux-parity bug worth fixing, just
NOT this abort.

ABORT MESSAGE: uncapturable after 4 tries (fd-2 write, sendmsg, worker-thread comms,
atomic writes). The greeter's thread I/O is ~all BINARY (Wayland/dbus/GL); NO glibc
"malloc(): corrupted" writev among 288 writes ⟹ NOT a glibc heap-corruption abort. The
abort is SILENT (bare abort()/qFatal to a binary journald frame). Self-sent SIGABRT (run5
SIGSEND), no kernel fault.

LEADING EXPLANATION now (COW agent's reframe): it may NOT be memory corruption at all —
a COMMON-CAUSE event during EARLY GL/Mesa/llvmpipe setup (before scanout) makes BOTH Qt
clients (greeter + wallpaper, and llvmpipe-using kwin) qFatal at once. SMP-only ⟹ a race,
not a deterministic failure. Suspects: a shared EGL/GL/Mesa init failure on renderD128
(kms_swrast/GBM), or a shared Wayland/compositor failure. NEXT: errors-only syscall trace
scoped to the greeter/llvmpipe (trace_comm + trace_errors_only) to catch the FAILING
syscall right before abort (a renderD128 ioctl EINVAL, a connect() refused, etc.); or
force the qFatal text to stderr via the greeter's env (QT_LOGGING/QT_FORCE_STDERR).

## ★ CURRENT STATE (2026-09-04) — read this first ★

CONFIRMED ROOT of the black screen: SMP-SPECIFIC USER-MEMORY CORRUPTION. On 16-vCPU
boots the plasma-login GREETER (pid ~14, plasma-login.service) AND WALLPAPER (pid ~15,
plasma-wallpaper.service) — two SEPARATE processes — silently `abort()` (SIGABRT,
core_dumped, NO kernel page-fault) during EARLY startup, at the SAME instant. kwin runs
them via `--exit-with-session`, so when they die kwin exits and systemd restart-loops
`plasma-login-kwin_wayland.service` (~17×) → black screen. kwin is a VICTIM, not a cause.
DEFINITIVE discriminator: `NARF_QEMU_SMP=1` → ZERO abort, kwin reaches scanout. (Repro:
`NARF_VBLK_IMG=/home/daniel/vms/cachyos-debug-copy.raw NARF_QEMU_MEM_MB=8192
NARF_QEMU_CPU=host XTASK_QEMU_SNAPSHOT=1 cargo xtask systemd-pid1 --arch x86_64
--features stall-watchdog,unix-latency-trace,cgroup --display none` — the USEREXIT/PARKREP
census + the widened kwin/greeter exit probes surface `killed_by_signal=6 core_dumped=true`.)

RULED OUT this session (TESTED — do NOT re-chase; the older "THIRD blocker"/kwin/epoll/
block sections below are all SUPERSEDED):
- Block layer (root fs is sync busy-poll via SyncBlock, correct), DRM card node (kwin opens
  card0 fine), epoll accept-wake (registry shares the listener Arc — correct), TLB-shootdown
  layer (fable audit: all mapping-change sites do a correct cross-CPU shootdown in this config).
- ALL 4 switch-path FPU/TLS/CR3 perf optimizations — XSAVEOPT, lazy-FPU restore, FSGSBASE,
  CR3-retention — bisected OFF individually (runs 8-11) AND all-4-off combined (run12): greeter
  STILL aborts. NOT the recent perf commits; this is PRE-EXISTING (matches "KDE FLAKY" history).
- Device DMA into user frames (fable audit: every device DMAs only to alloc_coherent).
- rseq (run13: rseq→-ENOSYS did not stop the abort; glibc ptmalloc doesn't use rseq).

SHARPEST OPEN LEAD (untested): SHARED-FRAME (COW) CORRUPTION. Two independent processes
aborting together ⇒ they share a corrupted frame = a common library page (libc/libQt, mmap'd
MAP_PRIVATE, physically shared until COW). Suspect an SMP COW-break race on CROSS-PROCESS
file-backed / page-cache pages — the corner the TLB audit did NOT cover (it checked only the
thread/`vm_shared` COW path). Next: audit the write-fault COW break for a file-backed /
page-cache-shared frame under SMP (private copy installed + shared frame refcount + full
shootdown BEFORE the faulting write retries?). Alt tool: poison-on-free + check-on-alloc on
the user frame/page-cache allocator to catch the stray write's RIP. Also still-uncaptured: the
greeter's abort MESSAGE (not a glibc writev to fd 2 — run14 got 0; likely Qt qFatal → journal
sendmsg, or silent).

FIXES from this session (on branch `feat/vt-layer-seat0`, rebased on origin/main):
- COMMITTED: VT layer (logind seat0 activation) + sys_read O_NONBLOCK park fix.
- UNCOMMITTED, real: `sys_rseq` → -ENOSYS (was faking success; Linux-correct, glibc falls back).
- UNCOMMITTED, diagnostics only: widened USEREXIT kwin/greeter exit probes (sys_exit_group.rs,
  core.inc.rs, compat.inc.rs), PARKBLK (trap.rs), PLWRITE/PLWRITEV stderr capture (sys_write.rs,
  sys_writev.rs). Gated on unix-latency-trace (+ the exit ones also fire under cgevt_trace).

INDEPENDENTLY-LANDABLE side-bugs found (not the black-screen root): evdev EVIOCREVOKE→EFAULT
(no handler); logind VT-restore→ENOTSUP (vt.rs gap); latent PCID shootdown bug (bare-metal
Zen2/Zen4; arch/src/x86_64/pcid.rs:389 has invpcid_addr); rt_sigframe carries no FP state
(userspace/src/syscall.rs:~4016); ext2 fill_lock convoy + page_cache.clear-on-every-write
(volume.rs:1072-1128); DRM dumb-buffer/PRIME frees frames while a user mmap/dma-buf still
targets them (DriCardFile lacks mmap_lifetime).

WORKAROUND (SUPERSEDED): `NARF_QEMU_SMP=1` used to boot far enough for KWin
to scan out, but the post-rebase 2026-09-04 GTK/virgl retest produced no vgpu0
surface. There is currently no verified graphical-login workaround.

## 2026-09-01 FACT-CHECK — what is stale in this doc, and the current layout

Pulled/verified against the local tree on 2026-09-01. Several load-bearing
facts in the older sessions no longer hold. Corrections, most important first:

### 1. The CachyOS disk image MOVED

- **Now:** `/home/daniel/vms/cachyos-fresh.raw` — a 40 GiB GPT disk (12 GiB
  sparse on-disk), partition 1 = 4 GiB EFI System, partition 2 = 36 GiB Linux
  filesystem. This is the real install. Modified 2026-08-25.
- **Doc's old path `target/cachyos-ext4-narf.raw` no longer exists**, and
  neither does `target/narf-fedora-vblk.img`. Any command below that names
  those paths must be pointed at the new image (or a rebuilt Fedora fixture).
- Installer ISO is still present: `/home/daniel/Downloads/cachyos-desktop-linux-260809.iso`.
- Boot it with `XTASK_QEMU_SNAPSHOT=1` so guest writes are discarded and the
  install can't be damaged.

### 2. The boot-level fixes ARE on `main` now (doc says they're branch-only)

The older "Git state" section says "Do not put these commits on main." That is
overtaken. As of 2026-09-01 the ext4/EFI/mount-ns/DRM boot fixes are all
ancestors of `main` HEAD (`aad60fdd`), under rebased hashes — verified:

| subject | on main as |
|---|---|
| Enable checksum-safe ext4 metadata writes | `a5d68bed` |
| Alias filesystem UUIDs as systemd devices | `426a7b03` |
| Replay DRM coldplug to graphical login | `80925e2a` |
| Resolve directory mutations in the caller's mount namespace | `ab93d1a3` |

So a CachyOS boot **from `main`** clears the kernel + ext4 + systemd/udev
boot-level gates. What it does NOT have is the desktop-bringup work (see #3),
so it is expected to stall before a usable Plasma desktop/login.

### 3. The CachyOS DESKTOP bringup lives on `origin/drm-master-arbitration`

- `origin/drm-master-arbitration` is **321 commits ahead of main, 0 behind**
  — a large active branch cleanly rebased on today's main. This is where the
  login-hang fix (SO_PEERGROUPS optlen), DRM-master arbitration, writable-/home
  tmpfs, DRM vblank pacing, etc. actually live. Tip `852bfc59`.
- The memory-note hashes `4e568c54` / `97b09abc` / `9b99f14c` are **pre-rebase
  and no longer resolve to any branch head** (`git branch --contains` is empty).
  Their *content* is on `drm-master-arbitration` under new hashes. Don't cite
  the old hashes.
- Other origin branches present: `cachyos-desktop`, `cachyos-efi` (the old
  branch this doc was written on).

### 4. `git pull` on this box fails on fetch (no ssh-askpass)

`git pull` errors with `ssh_askpass: exec(/usr/lib/ssh/ssh-askpass): No such
file or directory` → `Permission denied (publickey)`. It is not a repo problem;
the SSH agent/askpass isn't wired for non-interactive fetch. Local `main` was
already at `origin/main` from the last successful fetch (0/0 divergence). To
re-fetch, run `! git pull` from an interactive prompt (or fix the agent).

### 5. Current reproduce command (updated paths + flags)

`--gpu-backend virgl` requires a GL-capable display; xtask's `--display` is a
free-form QEMU display string, so pass `gtk,gl=on` (the old `--display gtk`
does not enable GL for virgl). Host has `DISPLAY=:0`.

```bash
env DISPLAY=:0 \
  NARF_QEMU_MEM_MB=8192 XTASK_QEMU_ACCEL=kvm XTASK_QEMU_SNAPSHOT=1 \
  XTASK_QEMU_QMP=/tmp/cachy_qmp.sock \
  NARF_VBLK_IMG=/home/daniel/vms/cachyos-fresh.raw \
  XTASK_SYSTEMD_PID1_TIMEOUT_SECS=600 \
  CARGO_BUILD_JOBS=4 \
  cargo xtask systemd-pid1 --arch x86_64 --features container \
    --hw-profile full --display gtk,gl=on --gpu-backend virgl
```

For the best shot at an actual desktop, run the same command from
`origin/drm-master-arbitration`, not `main`.

### 6. Boot-from-`main` result (2026-09-01, GTK/virgl, snapshot)

Booted `/home/daniel/vms/cachyos-fresh.raw` on `main` (`aad60fdd`) with the
command in #5. How far it got:

- **Kernel: clean.** No kernel panic, no STALL-WD, no `panicked at` anywhere in
  the whole capture. 16 CPUs online, ext4 root mounted, real systemd 261-class
  PID 1, "Welcome to CachyOS!".
- **Reached `Local File Systems`, `Basic System`, `Login Prompts`** — a
  `narf login:` getty prompt appears on serial, and systemd even logs
  **"Started Plasma Login Manager"**.
- **No graphical desktop.** QMP `screendump` on vgpu0 = **"no surface"** — no
  compositor ever SET_SCANOUT, so the GTK window stays black. Because:

**PRIMARY BLOCKER — ROOT-CAUSED + FIXED: `capset` ignored `PR_SET_KEEPCAPS`.**
`dbus-broker` (System Message Bus) crash-loops → FAILED (starts ~4×, trips
systemd's start-limit). That cascades: **`systemd-logind` fail-loops forever**
(needs the system bus) → no seat → no session. Traced with
`--features container,syscall-trace` + `trace_comm=dbus-broker` (prefix catches
`dbus-broker-launch`). The failing child's sequence (comm `dbus-broker-lau`):

```
prctl(PR_SET_KEEPCAPS=8, 1) = 0     capset(...) = 0     (permitted set while root)
setresgid(81,81,81) = 0   setgroups(0) = 0   setresuid(81,81,81) = 0   (root→messagebus)
prctl(PR_SET_KEEPCAPS=8, 0) = 0     capset(...) = -1    ← EPERM, then exit_group(1)
```

This is the keepcaps privilege-drop dance (`dbus-broker-launch --audit` retains
`CAP_AUDIT_WRITE`). On Linux `PR_SET_KEEPCAPS(1)` sets `SECURE_KEEP_CAPS`, so
`security/commoncap.c::cap_emulate_setxuid` does NOT clear the permitted set on
the root→non-root `setresuid`; the final `capset` re-raises effective from the
retained permitted → 0. NARF's `cap_emulate_setxuid` (an explicit `// LINUX-GAP`
at core.inc.rs) ignored keepcaps and always zeroed permitted, so the final
`capset` saw `old.permitted == 0` → EPERM → broker child aborts → no bus.

FIX (this session, on `main`, NOT yet committed): gate the permitted/effective
clear on the already-stored `read_prctl(task).keep_caps` (ambient is still
cleared unconditionally, matching Linux). RED→GREEN tests added to
`userspace/src/abi_creds_tests.rs`:
`smoke_abi_caps_keepcaps_retains_permitted_across_setuid` (pos) and
`smoke_abi_caps_no_keepcaps_clears_permitted_across_setuid` (neg guard), plus a
`__test_cap_emulate_setxuid` hook. General correctness fix — every keepcaps-dance
daemon (sshd, etc.) was affected.

NB: the parent launcher's `getsockopt SO_PEERSEC(31)/SO_PEERPIDFD(77) = -92`
(ENOPROTOOPT) in the same trace are CORRECT — NARF has a test asserting
ENOPROTOOPT for SO_PEERSEC without an LSM, and SO_PEERPIDFD is legitimately
unimplemented; dbus handles both gracefully. The SO_PEERGROUPS/SO_PEERCRED
optlen work is already on main too. capset was the only wrong return.

**AFTER THE capset FIX (boot-verified, GTK/virgl, snapshot):** the bus comes up
clean — `[ OK ] Started D-Bus System Message Bus` (no crash-loop) — and the boot
now reaches `[ OK ] Reached target Multi-User System`, `[ OK ] Started Plasma
Login Manager`, and `[ OK ] Reached target Graphical Interface`. Screen still
black (`screendump` = "no surface") because the NEXT blocker is exposed:

**NEXT BLOCKER — `systemd-logind` (User Login Management) fail-loops even with
the bus up.** It does NOT segfault (zero `fatal-fault` records) — it exits
non-zero cleanly, the same wrong-syscall shape capset had, so it's a strong
candidate for another Linux-errno mismatch. Being traced with
`trace_comm=systemd-logind trace_errors_only` (comm fits in 15 chars). Without
logind there's no seat → the Plasma login manager gets no session → no
compositor takes the DRM device → no scanout. (rebased onto HEAD 8eb6a849, which
also carries the orthogonal UEFI early-fb-console PR #252.)

Note: `ananicy-cpp` still SIGSEGVs (BPF skeleton open — see above); harmless.

**logind diagnosis attempts (2026-09-01, all walls):**
- logind emits ZERO syscalls under its own comm and no `[process-exit]` → it
  never exec's; the failure is in systemd-executor's per-service SETUP, before
  exec. NetworkManager fails identically (instant, no timeout). dbus/avahi
  succeed (avahi does the same cap-drop and works after the capset fix).
- `trace_comm=systemd-logind` / `systemd-executo` / `(sd-executor)` all captured
  NOTHING — the setup child's comm matches none of those, and
  `trace_errors_only` WITHOUT a `trace_comm` is inert (emits nothing).
- Global `systemd.log_level=debug systemd.log_target=console` on the cmdline is
  too slow (61k lines, never reached dbus before the 200s timeout — observer
  effect).
- Targeted logind debug drop-in (via debugfs): the real image has a dirty
  journal (`needs_recovery`); debugfs-writing it offline CORRUPTS it (booted with
  spurious /tmp + tracefs + debugfs mount failures). Must replay the journal
  first (loop-mount + e2fsck, needs sudo). Staged cleanly on a throwaway copy
  that way.
- Booting the clean drop-in copy with `SYSTEMD_LOG_LEVEL=debug` → **KERNEL PANIC:
  `memory allocation of 5104 bytes failed`** right at the logind/NM/avahi start
  burst. The debug flood overruns journald's stdout backlog (kernel-allocated
  socket buffers) → kernel heap OOM. Confirmed observer effect: the SAME branch,
  real image, NO drop-in, reaches Graphical Interface with no panic — so it is
  NOT a #253 regression and NOT the capset fix. The debug drop-in is unusable at
  `debug` level; a lighter one (StandardError=journal+console, NO debug level)
  is the untried next step, but needs another sudo re-stage.
- Lighter drop-in (StandardError=journal+console, NO debug) — no OOM this time,
  but under SMP=1 logind's start job RUNS ~80s then TIMES OUT (`start job is
  running for User Login Management (1min 20s / 1min 21s)`), and Avahi + NM time
  out too. On the CLEAN SMP=16 boots logind instead fails FAST, 12-14× (no
  timeout progress lines). So the failure MODE itself shifts with the
  instrument: debug drop-in → kernel OOM; console-stdio + SMP=1 → 80s readiness
  timeout; clean SMP=16 → fast repeated fail. Classic "diagnostics change the
  failure" (feedback_diagnostic_observer_effect), severe here.

- **BIG CORRECTION: `origin/drm-master-arbitration` does NOT reach KDE with
  `cachyos-fresh.raw` either.** Booted it (852bfc59, full build, GTK): logind
  fail-loops 7×, kwin/plasmashell/greeter NEVER launch, screendump "no surface",
  settles at a text login. So logind is a blocker COMMON to both `main` and the
  desktop branch on this image — NOT something that branch solved. The branch's
  earlier "greeter presents" successes were on a different image/state (the old
  `cachyos-ext4-narf.raw`, now gone), not this fresh Aug-25 reinstall.

- GROUND TRUTH (clean, uninstrumented): on BOTH branches, SMP=16, real image —
  logind fails fast + repeatedly, never exec's (0 syscalls under its comm, no
  process-exit), no `Failed with result` at info level; dbus + avahi SUCCEED
  (avahi does the same cap-drop, works after the capset fix); NetworkManager
  fails like logind. Boot still reaches Graphical Interface; screen black; no KDE.

- NOT YET ISOLATED: the exact executor-setup step/errno that fails logind (and
  NM) fast-and-pre-exec. Every instrument contaminates it. Untried clean idea:
  add syscall-trace and trace the executor by its ACTUAL comm — find that comm
  first (trace `systemd` broadly for one boot, grep the child that forks right
  at "Starting User Login Management", note its comm, then re-trace just that).
  logind is a real, separate, HARD blocker — bank the capset fix; treat logind
  as its own milestone.

Throwaway debug copy at `/home/daniel/vms/cachyos-debug-copy.raw` (12 GiB) — safe
to delete; the real `cachyos-fresh.raw` was never modified.

**Capset fix SHIPPED (2026-09-02):** merged to `origin/main` as PR #256
(`93330d2e caps: honor PR_SET_KEEPCAPS in the setuid credential fixup`, merge
`e37b807b`). Also new on main since: #253 virtio-mmio, #254 CI, #255 unmap AP
trampoline after SMP. Re-tested boot on this updated main: identical — dbus up,
Graphical Interface reached, logind fail-loops 6-7×, no KDE. The other fixes do
NOT touch logind.

**On "watch it boot in GTK":** the GTK window shows only a small RGBW GPU
init test square (top-left) on black — the kernel/systemd console goes to
SERIAL, not the virtio-gpu. `--gpu-backend virgl` → `screendump` "no surface";
`--gpu-backend virtio-2d` → a surface exists but only the test pattern. The GPU
is painted ONLY by a Wayland compositor (kwin/greeter), which needs logind.
So there is nothing to watch in the window until logind is fixed — it stays
black regardless of branch/display.

**BPF errno fix (2026-09-02, correct but NOT the logind fix):** NARF's
`prog_load` returned `-ENOTSUP` (-95) for an unsupported prog type
(CGROUP_DEVICE etc.); verified against `~/git/linux` (kernel/bpf/syscall.c:2279
`find_prog_type`) that Linux returns `-EINVAL` for ANY type not backed by ops
(out-of-range OR NULL-ops). The kernel's BPF_PROG_LOAD never emits EOPNOTSUPP
for the prog-type check, so systemd's `bpf_devices_supported`/
`bpf_firewall_supported` probes (which load a CGROUP_DEVICE/CGROUP_SKB program
to read this errno) got a value Linux never gives. Fixed `sys_bpf.rs:546`
`_ => -ENOTSUP` → `-EINVAL`, updated `abi_bpf_tests.rs` (the tests encoded the
wrong errno) + added a CGROUP_DEVICE case. BUT boot-verify: **logind STILL fails
6×** — so the bpf errno was NOT the blocker. (First boot after the change wedged
at 789 lines pre-dbus; a 2nd run reached Graphical Interface — so that wedge was
CachyOS variance, not the change.) Keep it anyway: it's a real Linux-errno match
in the area systemd probes. NOTE the `EOPNOTSUPP`-for-unimplemented-type
convention is ALSO wrong for map_create (`abi_bpf_tests.rs:1094`) and attach
(`sys_bpf_attach.rs:289`) vs Linux's EINVAL — a broader follow-up.

**logind's fatal step has NO erroring syscall.** The clean errors-only trace
(ananicy masked, comm=systemd-executo,systemd) reached logind fast: the only
executor errors are benign — `mkdirat=-17` (EEXIST), `lgetxattr/removexattr=-61`
(ENODATA), `getsockopt=-92` (SO_PEERSEC/PEERPIDFD, established-correct), and
`prctl(PR_SET_MM ARG_START/END)=-22` which EVERY executor hits yet dbus/avahi
still start (so best-effort, non-fatal). The `bpf=-95` calls were all PID1
(t=15) doing cgroup device-controller setup, which PID1 survives (degrades).
So logind's executor fails via a syscall that RETURNS SUCCESS but whose result
it rejects, or internal logic — no errno to fix, which is why it evades tracing.
A FULL executor trace floods (79k lines) before reaching logind. Next idea to
make a full logind-executor trace feasible: mask the pre-logind services
(resolved, etc.) so the boot reaches logind with far fewer executor invocations
to trace. Also worth: fetch systemd-executor source and read what a
CapabilityBoundingSet=+DeviceAllow= unit's setup does that returns a
success-but-rejected value.

## 2026-09-02 ★★★ FIXED: `sys_mknodat` dropped its dirfd — logind now starts ★★★

The `ProtectKernelLogs` failure (below) traced to a one-line bug: **`sys_mknodat`
ignored its `dirfd`** and passed only the relative pathname to `mknod_common`,
which resolved it against the CWD. systemd creates the per-boot sandbox nodes
`/run/systemd/inaccessible/{reg,chr,blk,fifo,sock}` with
`mknodat(fd_of_inaccessible_dir, "sock", …)` — RELATIVE + dirfd — so the nodes
landed under the CWD, never at `/run/systemd/inaccessible/`. Every service whose
sandbox binds one of those nodes over a path (`ProtectKernelLogs=` over
`/dev/kmsg`, and by the same mechanism `ProtectClock=`/`ProtectKernelTunables=`/…)
then failed namespace setup 226/EXIT_NAMESPACE because the bind SOURCE didn't
exist. On this image that's `systemd-logind` + `NetworkManager` +
`systemd-resolved`. (`/inaccessible/dir` was unaffected — it's made with
`mkdirat`, which already honored the dirfd.)

HOW IT WAS FOUND: bisected the failure to `ProtectKernelLogs=yes`, then
instrumented the mount/mknod paths (temporary `narf_console::Writer` prints).
The bind of `/run/systemd/inaccessible/sock` over `/dev/kmsg` returned
`NotFound` (source didn't exist), and `KMSGDBG mknodat dirfd=0x5 path="sock"`
showed systemd using a relative path + dirfd that NARF was dropping.

FIX (userspace/src/handlers/sys_mknodat.rs + sys_mknod.rs + core.inc.rs):
`mknod_common` now takes a resolved path `&str`; `sys_mknod` copies its cstr;
`sys_mknodat` applies the dirfd via `resolve_at_path` (EBADF/ENOTDIR come back
like openat/mkdirat). VERIFIED: a `ProtectKernelLogs=yes`-only oneshot unit that
FAILED now `[ OK ] Finished`; on the copy `systemd-logind` `[ OK ] Started`,
`New seat seat0`, `New session 'c1' of user 'plasmalogin' class 'greeter' type
'wayland'` — logind + seat + greeter session all up, FAILED=0.

REMAINING (NOT this bug): (1) boot now stalls one layer further at "Starting
Plasma Login Manager" — kwin_wayland/GPU rendering, the deep desktop-bringup on
`origin/drm-master-arbitration`. (2) On the REAL image (ananicy crash-loop
unmasked + dirty journal) one GTK boot still showed logind failing 7× where the
clean copy succeeds — investigate variance / ananicy interference vs a genuine
image-state difference (the fix itself is proven by captest-t + the copy).

CHERRY-PICKED ONTO drm-master-arbitration (local branch, commits b329df08 bpf +
04b59a0c mknodat; the core.inc.rs cherry-pick conflicted on that branch's OLDER
mknod_common — resolved by keeping its body + `fail` sentinel and applying only
the `raw_path`/dirfd change, NOT main's mode-validation block). Built + GTK
booted: logind `[OK] Started`, seat0, greeter session c1 (wayland),
`SESSION-EXEC /usr/bin/kwin_wayland`, and kwin `SESSIONBUS-CONNECT
/run/user/957/bus by=QDBusConnection` — so kwin RUNS. Then it HANGS: no
SET_SCANOUT, screendump "no surface", console idle for minutes, no fatal-fault
(hung, not crashed), across 2 boots. That is the kwin/compositor-present gate
this branch is separately working on (memory: kwin freezes/flaky), downstream of
everything the mknodat fix unblocks. NEXT for the desktop: kwin_wayland's hang
after the session-bus connect on drm-master-arbitration — trace kwin (comm
`kwin_wayland`) to find where it blocks (GPU/DRM-master handoff, a wayland
socket, or a Qt/dbus wait).

## 2026-09-02 boot on `main` @ 6947ddc7 (futex fixes) + ananicy crash root-caused

Booted `cachyos-fresh.raw` (snapshot, GTK/virgl, SMP=16) on `main` with PR #260's
futex perf fixes in. Result:
- Reached **Graphical Interface** target + **"Started Plasma Login Manager"**.
- But **`systemd-logind` (User Login Management) failed 7×** → greeter gets no
  seat → QMP `screendump` vgpu0 = "no surface" (black). This is the known
  real-image logind pattern; the futex fixes are a perf win but don't touch it.
- **`ananicy-cpp` crash-loops**: deterministic `SIGSEGV #PF faultva=0x10
  rip=0x80000668b6`, respawning forever — the CPU hog (qemu 446%).

### ananicy crash — ROOT-CAUSED (NOT a NARF errno bug)

SMP=1 syscall trace filtered to `ananicy-cpp` (cmdline `trace_comm=ananicy-cpp`
via `XTASK_QEMU_APPEND`, NOT the env var — the filter is a multiboot2 kernel
cmdline token parsed in frame/src/bare_main.rs:4396). Immediately before every
fault, ananicy (task 177) does exactly **3× `bpf` cmd=5 (BPF_PROG_LOAD), all
`-22 EINVAL`**, writes a 31-byte error to stderr, closes/munmaps, then
null-derefs at offset 0x10 with NO intervening syscall. No `BPF_MAP_CREATE`, no
partial-success — NARF hands back nothing inconsistent.

**NARF's EINVAL is CORRECT.** ananicy's BPF prog type isn't one NARF implements
(NARF accepts only XDP/RAW_TRACEPOINT/TRACING/SYSCALL — sys_bpf.rs:156-159); for
any other type Linux's `find_prog_type()` also returns EINVAL, and sys_bpf.rs:544
deliberately mirrors that (the comment cites kernel/bpf/syscall.c and notes
systemd's own BPF probes rely on EINVAL to "degrade gracefully"). So this is:
(1) a **LINUX-GAP** — NARF doesn't implement ananicy's prog type (socket/cgroup/
tracepoint; Phase 5/6, large, out of scope), plus (2) **ananicy's OWN latent
bug** — unlike systemd it does not fall back when BPF prog load fails, it
null-derefs the prog handle it never got. Not fixable from NARF's syscall layer,
and ananicy-cpp (auto-renice) is **non-essential** to the desktop.

**Action:** mask `ananicy-cpp` — it's a crash-looping CPU hog of zero desktop
value, and masking it also tests whether its churn is what starves/fails logind
on the real image (the clean copy, without this churn, brought logind up).

## 2026-09-02 "regression" DISPROVEN — it's IMAGE STATE, not code/futex

User reported: "at one point we were reaching the login screen and then hanging,
but now we aren't getting that far." Investigated as a regression. Result — NOT
a regression:

- **Futex PR #260 EXONERATED.** Booted `517934cc` (main MINUS the 2 futex
  commits) on `cachyos-fresh.raw`: logind fails **7× — identical** to the
  post-futex build. The futex/scheduler changes do not cause it.
- **It's the IMAGE, not the code.** Same commit (current main `f1bfb368`), two
  images, snapshot mode:
  - `cachyos-fresh.raw` (REAL install) → logind **fails 7×** → no greeter.
  - `cachyos-debug-copy.raw` (clean COPY) → `systemd-logind: New seat seat0` →
    **Started User Login Management** → Graphical Interface → `New session 'c1'
    of user 'plasmalogin' class 'greeter' type 'wayland'` → **`SESSION-EXEC
    path=/usr/bin/kwin_wayland`**. logind SUCCEEDS; the greeter launches its
    compositor.
- So "reaching the login screen" = the COPY (logind works); "now not getting
  that far" = this session booted the REAL image (bad state, logind fails). No
  code regression; current main reaches the greeter on the copy exactly as
  before.
- **The "then hanging" = the kwin no-present frontier, unchanged.** On the copy,
  kwin_wayland launches but screendump vgpu0 stays "no surface" (~360-456% CPU,
  busy) — it never SET_SCANOUTs. Same deep compositor frontier documented below.

TWO independent, non-regression blockers remain:
  A. REAL-image logind failure = that image's STATE (journal/config), not code.
     The copy proves the binary is fine. Needs the guest journal to know which
     step fails on that specific image.
  B. kwin no-present on the (working) copy = the compositor bringup frontier.

The desktop-reaching image is the COPY. Futex fixes are fully cleared.

## 2026-09-02 logind failure on the real image — narrowed (futex-fixes boot)

After the futex-fixes boot reached Graphical Interface but logind failed 7×,
drilled into WHY logind fails on `cachyos-fresh.raw`. Solid, trustworthy results:

- **Sandbox setup SUCCEEDS.** A syscall trace (comm=systemd-logind,executor)
  shows **0 errored mount/mknodat/move_mount/pivot_root** — the mknodat fix is
  holding. logind is NOT failing on an inaccessible-node overmount anymore.
- **Failure modes DIFFER by service** (both are ProtectKernelLogs):
  - **logind fails INSTANTLY** — "Starting User Login Management…" → "[FAILED]"
    with no delay. So it's an executor setup/exec step (or an assert/dependency)
    failing immediately, NOT a readiness timeout.
  - **resolved fails via a 15s readiness TIMEOUT** (Type=notify never signals
    ready), a different mode.
- **The reason is JOURNAL-ONLY.** `systemd.log_level=debug systemd.log_target=
  console` on the cmdline IS honored (the greeter/services react to it) but does
  NOT surface systemd's per-unit exec-failure lines ("Failed at step X",
  "About to execute", "Forked") on serial — those go to the journal. So the
  console can't tell us logind's exact failing step.
- **Trace observer effect is real here:** a FULL syscall trace of every executor
  is so heavy that `systemd-journald.service: start operation timed out` — the
  trace MANUFACTURES timeouts. Any future logind trace must be tightly scoped
  (only logind's own executor) or it drowns the boot.
- Incidental (non-fatal, degrade-OK): `systemd-journald.service: … does not
  support BPF/cgroup firewalling` (expected — NARF LINUX-GAP, journald
  continues); `systemd-vconsole-setup.service: … status=1/FAILURE`.

**To crack logind, the next tool is the guest JOURNAL** (its "Failed at step …"
line names the exact syscall/step). Options: loop-mount `cachyos-fresh.raw` at
offset 4256169984 read-only + `journalctl -D <mnt>/var/log/journal` (needs
sudo), or run `/usr/lib/systemd/systemd-logind` manually without the sandbox to
capture its stderr. Console-only diagnostics are exhausted.

### cmdline tooling notes (confirmed this session)
- `/proc/cmdline` = `narf_boot::cmdline()` verbatim (filesystem/src/procfs/mod.rs
  gen_cmdline) — systemd DOES see kernel-cmdline `systemd.*` tokens.
- `trace_comm=<prefix,prefix>` is a multiboot cmdline token (NOT an env var);
  pass via `XTASK_QEMU_APPEND=`. `trace_errors_only` SUPPRESSED all output when
  combined with trace_comm here (produced 0 lines) — use a FULL trace instead.
- `systemd.mask=ananicy-cpp.service` via cmdline did NOT stop ananicy — likely
  the wrong unit name (confirm the real unit before relying on it).

## 2026-09-03 FIX #2 LANDED: sys_read O_NONBLOCK park (commit 6d215b28)

Cracked the present-stall's first layer. Method: a scoped, rate-limited
"blocking-syscall for kwin" probe at the syscall dispatch (far less I/O than a
full trace, which changes kwin's behavior). kwin parked in `read(fd=30,
O_NONBLOCK, not-readable, type=Special)` — an evdev node. sys_read called
`poll_blocking(ops.read())` UNCONDITIONALLY, which PARKS on a Pending future,
and only checked O_NONBLOCK/nonblock_read_eagain AFTER — so an ops whose read()
future is Pending-when-empty (evdev blocks internally on an empty ring) parked a
non-blocking read forever, never returning EAGAIN. Exactly what
devfs_input::nonblock_read_eagain's comment intends but the check sat after the
park. Fix: for a non-blocking stream/char read, `poll_once` + map Pending→
WouldBlock→EAGAIN; keep poll_blocking for blocking reads + regular files.
Boot-verified: kwin advanced from ~75 blocking syscalls (parked at input) to
1822 (deep into startup). boot-smoke clean; socket/eventfd/pipe nonblock tests
are the regression coverage (they return WouldBlock, unaffected).

### rseq CLEARED; abort msg not on fd 2; SHARPEST remaining lead = shared-frame (COW) corruption

- run13 (sys_rseq → -ENOSYS): greeter STILL aborts (same RIPs, 18 kwin restarts). rseq is
  NOT the cause (glibc ptmalloc doesn't use rseq). BUT rseq → -ENOSYS is KEPT as a real
  Linux-correctness fix (faking success on preemptive SMP is the project's anti-pattern;
  glibc falls back to getcpu cleanly; boot reached greeter+kwin fine).
- run14 (fd-2 write/writev capture probe, PLWRITE/PLWRITEV for comm=plasma-login): ZERO
  captured, yet greeter aborted. ⟹ the abort is NOT a glibc __libc_message (those writev to
  fd 2). So it is a Qt qFatal → journal via sendmsg (buried in socket.rs, not a sys_sendmsg
  file), or a bare/silent abort. Message still uncaptured.

SHARPEST UNTESTED HYPOTHESIS (fits ALL evidence best): the greeter (pid14, plasma-login.service)
and wallpaper (pid15, plasma-wallpaper.service) are SEPARATE processes that abort at the SAME
instant, SMP-only, early startup. Two independent processes corrupting together ⇒ they share a
CORRUPTED FRAME — i.e., a SHARED read-only/COW page (a common library: libc/libQt, mmap'd
MAP_PRIVATE, physically shared until COW). An SMP COW-break race that lets a write land in the
SHARED file-backed frame (instead of/before the private copy) corrupts that library page for
EVERY process mapping it → all abort. The TLB audit checked cow_split's vm_shared (THREAD)
shootdown, but NOT the cross-process shared file-backed / page-cache frame COW-break path. THAT
is the next target: audit the write-fault COW break for a file-backed/page-cache-shared frame
under SMP — does the private copy get installed + the shared frame's refcount handled before
the faulting write is allowed to retry, with a full shootdown? A race here = exactly this bug.

Alt tooling: poison-on-free + check-on-alloc on the user frame/page-cache allocator to catch
the corruptor's write red-handed (RIP of the stray write). Best "who corrupts memory" tool.

### DMA AUDIT (fable agent) — NOT device DMA; rseq lead [rseq CLEARED by run13 — see rseq section above; kept only as a Linux-correctness fix]

Device-DMA-into-freed-frame hypothesis: REFUTED. Every virtio device (gpu, blk, net,
input, rng) DMAs only to alloc_coherent (driver-owned buddy frames); virtio-gpu scanout
+ 3D backing are alloc_coherent and pinned via MmapLifetime Arc for the mapping's life;
virtio-blk bounces through a coherent payload + copy_to_user. No device touches a
user-owned frame. (One real but WEAK CPU-side hole: DRM dumb-buffer/PRIME frees frames on
GEM_CLOSE/RMFB while a user mmap/dma-buf still targets them — DriCardFile lacks
mmap_lifetime, drm_devfs_bridge.rs:239-273; Linux pins via VMA/dma-buf. Fix later.)

REFRAME from the run12 log: greeter (pid14) + wallpaper (pid15) have PARKREP scans=0
checks=0 pnfds=0 (never parked/polled), abort at the SAME instant, RIPs = libc tgkill
inside abort(), and NO drm: line ⇒ they die during EARLY STARTUP (ld.so/libc/Qt static
init), NOT while rendering. Only 3 SIGSENDs total (2 SIGTERM→kwin, 2 self-SIGABRT); no
handler ran. So it is early-startup heap corruption, shared trigger on two CPUs.

⟹ STRONG LEAD (agent): `sys_rseq` (userspace/src/handlers/sys_rseq.rs) FAKES success
(returned ok(0)) without implementing rseq — never updates cpu_id, never restarts a
critical section on preempt/migrate. The "cooperative single-CPU" rationale is STALE
(NARF is preemptive SMP now). glibc >= 2.35 registers rseq at thread start; on success it
trusts the ABI (publishes __rseq_size!=0) so rseq users read a never-advancing cpu_id and
run critical sections un-restarted across a real CPU migration → SMP-only per-CPU-state
corruption → glibc heap abort(). PERFECT fit: SMP-only, user-heap, silent abort, early
startup, both apps at once, glibc >= 2.35 (CachyOS). This is also the project's recurring
"faked syscall success instead of the Linux errno" bug class.

FIX/TEST (run13, cachy_serial13_rseq_enosys.log): sys_rseq now returns -ENOSYS (38) — the
Linux behavior for a kernel without rseq; glibc leaves rseq unregistered and falls back to
getcpu(2). If the greeter SIGABRT (killed_by_signal=6) DISAPPEARS on 16 vCPU ⇒ rseq
confirmed as the black-screen root. (Alternative if it persists: capture fd-2 write payloads
for comm=plasma-login to serial for the exact glibc abort message; and sys_getcpu/getcpu
correctness.)

### DEFINITIVE — SMP corruption is NOT the switch-path perf commits (all 4 off, combined, still aborts)

run12 (all 4 toggles OFF together, 16 vCPU): greeter+wallpaper STILL abort
(plasma-login-gr pid14 + plasma-login-wa pid15, killed_by_signal=6, core_dumped=true,
same RIPs). ⟹ CONCLUSIVE: XSAVEOPT / lazy-FPU / FSGSBASE / CR3-retention are NOT the
cause, individually or combined. Agent's switch-path-perf hypothesis: FULLY REFUTED.
All 4 bisect toggles reverted (tree clean; they fixed nothing).

STANDING CONCLUSIONS:
- Black screen = SMP-specific user-heap corruption → greeter+wallpaper silent abort()
  (SIGABRT, no kernel fault) → kwin (--exit-with-session) exits → systemd restart-loop.
- CONFIRMED SMP-specific: NARF_QEMU_SMP=1 → ZERO abort, kwin presents (SETCRTC markers).
- RULED OUT: block layer, DRM card node, epoll accept-wake, TLB-shootdown layer (all
  code-audited correct), and all 4 switch-path FPU/TLS/CR3 perf optimizations (bisected).
- So it is a PRE-EXISTING SMP corruption bug (predates the recent perf commits; matches
  the long-standing "KDE visible desktop FLAKY" history), NOT a regression.

REMAINING CANDIDATES (agent's fallback + reasoning) for the next hunt:
1. Driver DMA into freed/reused frames — virtio-gpu/virgl scanout+backing-store lifetime,
   virtio-blk direct-to-user reads. A device DMAing into a frame after a user process
   freed+reused it corrupts that heap. Strong fit (greeter/wallpaper are GPU/render-heavy).
2. Per-CPU slab/allocator race under SMP (kernel slab magazine / percpu cache).
3. A deeper paging bug not on the switch path (e.g., a COW/fork race that the TLB audit's
   vm_shared reasoning doesn't cover in a corner case).
Tooling ideas: KASAN build (--kasan) for kernel-side corruptors; a poison-on-free +
check-on-alloc on the user frame allocator; or bisect to the FIRST commit where the
greeter abort appears (needs VT+sys_read cherry-picked onto old bases — confounded).

WORKAROUND (usable now): NARF_QEMU_SMP=1 boots the desktop far enough for kwin to scanout.

INDEPENDENTLY-LANDABLE bugs found this session (not the black-screen root, but real):
- evdev EVIOCREVOKE → EFAULT (no handler; Linux returns 0).
- systemd-logind VT-restore → ENOTSUP (vt.rs gap).
- latent PCID shootdown bug (bare-metal Zen2/Zen4; arch/src/x86_64/pcid.rs:389 has invpcid_addr).
- rt_sigframe carries no FP state (userspace/src/syscall.rs:4016).
- ext2 fill_lock convoy + page_cache.clear-on-every-write (volume.rs:1072-1128).

### BISECT RESULTS — all 4 switch-path toggles FAIL individually (greeter still aborts)

Tested each of the agent's 4 kill-switches on 16 vCPU; greeter+wallpaper STILL abort
(killed_by_signal=6, core_dumped, same RIPs 0x4090028812eb/0x4090025ae2eb) in ALL:
- run8 XSAVEOPT off (xsave.rs, FPU_USE_XSAVEOPT=false) → abort persists.
- run9 eager FPU restore (stackful.rs user_fpu_restore_task, XRSTOR now vs arm trap) → persists.
- run10 FSGSBASE off (user_mode.rs enable_fsgsbase early-return; MSR FS_BASE path) → persists
  (kwin restarts dropped 18→2, but the abort still happened — likely variance).
- run11 CR3 retention off (lib.rs AddressSpaceHandoff::prepare always activate()) → persists.
⟹ No SINGLE switch-path optimization is the cause. Agent's specific-toggle hypothesis: REFUTED.
run12 = ALL 4 toggles ON together (combined-interaction test). If STILL aborts ⇒ definitively
NOT the switch-path perf commits ⇒ pivot to pre-existing SMP bug / other mechanism (per-CPU
slab/allocator race, driver DMA into freed frames, or a deeper paging bug). If GONE ⇒ it's a
COMBINATION → narrow.
NOTE: abort is still CONFIRMED SMP-specific (gone entirely on NARF_QEMU_SMP=1). Workaround
stands: SMP=1 gets kwin to scanout.

### SMP AUDIT (fable agent) — NOT a TLB bug; suspected switch-path FPU perf [REFUTED by bisect — see DEFINITIVE/BISECT sections above; all 4 toggles tested, none fixed it]

Independent SMP audit (read-only) result:
- TLB-SHOOTDOWN LAYER IS CORRECT in the failing config (KVM,16vCPU): every
  user-mapping-change site (COW/mprotect/munmap/madvise/mremap/fork/swap/OOM) funnels
  into a batched cross-CPU shootdown (memory/src/tlb_shootdown.rs), vm_shared-gated,
  residency-filtered, unbounded ack-wait. My missing-shootdown hypothesis: REFUTED.
- LATENT PCID bug (NOT active here — KVM exposes pcid=false, "domain enforcer: NONE"):
  under CR4.PCIDE=1, raw INVLPG (local + IPI receiver) invalidates only the current
  PCID, leaving the user PCID-0 entry live; syscall exit restores user CR3 NOFLUSH.
  Bites bare-metal Zen2/Zen4. Fix: invpcid_addr(0,va) after INVLPG when pcide_enabled
  (arch/src/x86_64/pcid.rs:389 has the primitive). Track separately.
- MOST LIKELY cause of the SMP greeter abort = the 2026-09-03 switch-path perf commits
  a6879919 (XSAVEOPT modified-opt + FSGSBASE + active_mm CR3 retention) and 74c78d8b
  (LAZY user-FPU restore via CR0.TS/#NM). Failure mode they own IS the symptom — the
  commit's own comment (scheduler/src/stackful.rs ~1717): "in-flight memcpy runs on
  another task's XMM/YMM → torn heap write → glibc abort() (SIGABRT)". Active in the
  failing config (xsaveopt/avx512/fsgsbase on; glibc EVEX memmove uses ZMM16-31). Agent
  found no STATIC hole; the only FPU test is single-CPU/no-migration.
- Secondary (real, not the driver): rt_sigframe carries no FP state
  (userspace/src/syscall.rs:4016) — an async signal mid-AVX-memcpy clobbers YMM.

BISECT IN PROGRESS: toggle #1 = XSAVEOPT off (arch/src/x86_64/xsave.rs:361 →
FPU_USE_XSAVEOPT=false; plain XSAVE always saves full mask = migration-safe). 16-vCPU
boot cachy_serial8_noxsaveopt.log. If greeter SIGABRT (killed_by_signal=6) DISAPPEARS ⇒
XSAVEOPT modified-opt is the culprit. If it remains ⇒ try toggle #2 (eager FPU restore:
replace arm_user_fpu_trap in user_fpu_restore_task with immediate
clear_task_switched()+xsave::fpu_restore(area)+live=true). Other toggles: #3 FSGSBASE
off, #4 CR3-retention off (delete Arc::ptr_eq early-return in AddressSpaceHandoff::prepare).

### CONVERGED ROOT — SMP-specific user-heap corruption (greeter abort is GONE on 1 CPU)

SMP=1 boot (cachy_serial7_smp1.log, NARF_QEMU_SMP=1): ZERO killed_by_signal=6 — the
greeter/wallpaper abort() DISAPPEARS on a single CPU. kwin restarts only ~2× (vs ~17×
on SMP) and there are 23 SETCRTC/present/scanout markers — kwin actually PRESENTS,
which it never stably did on SMP. (Reached plasma-login-greeter/wallpaper/wayland +
kwin; ran the full 418 s window; residual SIGKILL teardown + a couple kwin restarts,
but the CORRUPTION-abort is gone.)

⟹ ROOT (converged): the black screen is SMP-SPECIFIC USER-HEAP/MEMORY CORRUPTION.
Multiple CPUs corrupt the Qt apps' heaps → greeter + wallpaper abort() (silent, no
kernel fault) → kwin (--exit-with-session) follows → systemd restart-loops
plasma-login-kwin_wayland.service → black screen. On 1 CPU the corruption doesn't
happen, the greeter survives, kwin reaches scanout. Exact class of
[[project_smp_mallocng_unlocked]] (stale paging-structure-cache spurious #PF, missing
local INVLPG) — a missing TLB shootdown / paging-structure-cache invalidation on an
SMP mapping change (COW split / mprotect / munmap / demand-fault / fork) that a
heavily-mmap/thread Qt app trips.

FIX DIRECTION: hunt the SMP MM path that changes a user mapping without a full
cross-CPU TLB/paging-structure-cache invalidation. Candidates: cow_split, mprotect
downgrade, munmap/unmap, demand_alloc_page, fork clone_for_fork — check each does an
IPI TLB shootdown to all CPUs sharing the AS (not just local INVLPG, and not just the
faulting CPU). NARF_QEMU_SMP=1 is a TEMPORARY WORKAROUND that gets kwin presenting —
useful to confirm the greeter renders with a GTK display.

WORKAROUND TO VALIDATE: boot SMP=1 WITH --display gtk (NARF_QEMU_SMP=1, drop
--display none) — if the greeter login screen VISIBLY renders, SMP corruption is the
whole black-screen root and the fix is purely the SMP MM invalidation bug.

### GREETER ABORT IS A PURE USERSPACE abort() — no kernel fault; SMP-corruption suspected

journal→console boot (cachy_serial6.log, systemd.journald.forward_to_console=1)
REPRODUCED the greeter+wallpaper SIGABRT but did NOT surface a glibc/qFatal message.
Established:
- NO NARF page-fault / #PF / SIGSEGV to the greeter (grep clean). killed_by_signal is
  only 6 (abort, the "66"/"99" are interleaved 6/9s), 9 (SIGKILL teardown), never 11.
  ⇒ PURE userspace abort(), NOT a caught-and-reraised crash. No kernel MM fault at the
  moment of death.
- The greeter's Qt/KDE stderr goes to kwin_err.log (via --exit-with-session), which has
  NO abort/fatal/glibc line ⇒ the abort is SILENT (no printed message). journald
  forwards systemd/logind fine ("New session c1 ... greeter/wayland") but no greeter
  fatal. So the message is genuinely absent, not just unrouted.
- TWO Qt/QML apps (greeter pid16 + wallpaper pid17) abort in LOCKSTEP, silently, no
  kernel fault ⇒ signature of SHARED MEMORY/HEAP CORRUPTION. NARF's heap-corruption
  history in KDE apps is SMP-specific (stale paging-structure-cache spurious #PF,
  [[project_smp_mallocng_unlocked]]; [[project_brk_per_task_heap_uaf]]).

TEST RUNNING (cachy_serial7_smp1.log): NARF_QEMU_SMP=1. If the greeter STOPS aborting on
one CPU ⇒ SMP paging/TLB/heap-corruption bug (narrows the fix to the SMP MM path). If it
still aborts ⇒ not SMP-specific (look at a single-CPU MM/mmap/COW path or a common Qt
qFatal). Decisive cheap discriminator.

### ROOT FOUND — the plasma-login GREETER aborts (SIGABRT), black screen follows

Mining the widened USEREXIT probe in the existing logs (cachy_serial5.log line 2375,
two interleaved lines deinterleaved):
  USEREXIT pid=16 tid=216 comm=plasma-login-gr killed_by_signal=6 core_dumped=true
           ip=0x4090028812eb cg=.../user@957.service/session.slice/plasma-login.service
  USEREXIT pid=17 tid=217 comm=plasma-login-wa killed_by_signal=6 core_dumped=true
           ip=0x4090025ae2eb cg=.../background.slice/plasma-wallpaper.service
(The earlier "signal 66" was TWO interleaved "signal 6"s — SIGABRT. Clean grep across
the run shows only killed_by_signal=9 ×12 [session-teardown SIGKILL] and =15 ×1 [kwin
SIGTERM]; the SIGSEND shows sig=6 SELF-sent = abort().)

⟹ ROOT: the plasma-login GREETER (plasma-login-greeter pid 16) AND the wallpaper
process (plasma-login-wa pid 17) both call abort() → SIGABRT(6) + coredump, at
user RIPs 0x4090028812eb / 0x4090025ae2eb. kwin runs the greeter via
`--exit-with-session` and exits when it dies → systemd restart-loops
plasma-login-kwin_wayland.service → BLACK SCREEN. kwin is a VICTIM, not the cause.

TWO Qt/QML apps aborting in lockstep ⇒ a SHARED NARF-induced fault, most likely HEAP
CORRUPTION (recurring KDE-app class: [[project_smp_mallocng_unlocked]],
[[project_brk_per_task_heap_uaf]]) or a common QML/EGL/Wayland qFatal. The abort
REASON (glibc "malloc(): corrupted"/"free()" or Qt qFatal text, printed to stderr
just before abort) is NOT in kwin_err.log — the greeter is its own systemd service, so
its stderr goes to the JOURNAL (tmpfs, discarded on snapshot boot). UNCAPTURED.

NEXT (get the abort reason, pick one):
- Boot with `systemd.journald.forward_to_console=1` (kernel cmdline via
  XTASK_QEMU_APPEND) so the greeter's journal stderr — including the abort message —
  lands on serial. Floods, but captures the qFatal/glibc line.
- OR symbolize the abort RIPs (0x4090025ae2eb, 0x4090028812eb) against the greeter
  binary + its load map (INTERP-BIAS region 0x4090_0000_0000-ish).
- OR KDE_DEBUG=1 in the greeter env to bypass KCrash so the ORIGINAL fatal (if a
  caught crash re-raised as abort) surfaces with its true signal/RIP.
Then chase the shared fault (suspect heap corruption in Qt/QML apps).

### INDEPENDENT AUDIT (fable agent) — corrections + refined root

An independent code audit (fable model, read-only) checked the conclusions below
and corrected several. Trust these over the older framings:

- epoll accept-wake path CONFIRMED correct: the LISTENERS registry holds the SAME
  Arc<SocketFile> the acceptor's fd points at (listen() inserts self.clone(),
  socket.rs:4007-4010); fork/CLONE_FILES/SCM_RIGHTS all share the Arc (fd.rs:1417-1442,
  1489; socket.rs:975-979). No cell split. DO NOT edit epoll. (One minor ET
  divergence — a notify landing between the ready-list snapshot and the delivered-fd
  write-back can be erased, epoll.rs:539-563 vs 664-703 — only bites a NON-draining
  ET consumer; journald is level-triggered. Not the strand.)
- The "uncategorized park, all wait-fields 0 + frozen checks" signature is UNIQUELY
  `park_pending_future` (core.inc.rs:446-470; checks only bump in own_stack_park,
  user_task.rs:843) — a syscall awaiting an FS-LAYER async lock, NOT a socket
  lost-wake. recvmsg never parks (returns -EAGAIN); AF_UNIX connect never blocks.
  The agent checked fill_lock/scratch/inode/position wake paths and found NO lost
  wake (mutex.rs drop wakes under the same lock arm registers under; return_scratch
  wakes oldest; stackful awake-cell cleared before dispatch). So the block/FS layer
  is NOT a lost-wake — but my "block layer fully cleared, kwin parks on
  epoll/futex/poll" was an OVERREACH: the ext2 ASYNC locks ARE what park with
  idle_halt + all-zero fields.
- MY CENSUS OVER-READING (corrected): kwin "appears once" = ONE 10s snapshot, not a
  strand (my own two-equal-samples rule was NOT met). journald checks=0-2 means it
  CYCLED through own_stack_park between reports (not permanently parked); epfd_enc=0
  is just an fs-park snapshot (epoll_wait_fd only set inside an epoll_wait park).
  "PID1 scans=59 frozen" was structurally uninformative (dbg_poll_scans only bumps in
  poll_common, poll.rs:903 — never for epoll parks). So "journald stuck early" and the
  "PID1 accept-strand" were artifacts. Retract them.

REFINED ROOT (audit + log check): kwin runs as plasma-login-kwin_wayland.service with
`--exit-with-session <greeter-cmd>` (argv cap hides it; kwin propagates the SESSION
CHILD's exit code). The greeter session command exits SILENTLY with failure (-1/255,
15) → kwin's service "fails" → systemd restart-loops it → black screen. systemd --user
MANAGER is STABLE (only clean code-0 helper exits in user@957; no manager restart, no
tree SIGTERM). So the black-screen root = the GREETER SESSION's silent failure-exit,
still UNCAPTURED.

REAL SECONDARY BUG (audit, fixable + kernel-testable, no boot): ext2
`write_byte_range` clears the ENTIRE page cache under the volume-wide `fill_lock` on
every sector write and writes one sector per virtio round-trip (volume.rs:1072-1128).
journald's continuous appends serialize every DSO fault-in behind a volume-wide mutex
— a convoy that makes the desktop LOOK stranded under a sampler and likely fuels the
boot flakiness. Worth fixing regardless.

NEXT (root): boot with KDE_DEBUG=1 in kwin's/greeter env → disables KCrash's handler,
so a CAUGHT greeter/kwin crash surfaces as a NARF fatal-fault (RIP) instead of a silent
_exit. That names crash-vs-clean-exit(-1) and, if a crash, the location. Two RED-ABI
divergences also found: blocking recv() returns 0 (spurious EOF, no RIP rewind,
sys_socket_recv.rs:107-141); blocking recvmsg() returns -EAGAIN (sys_socket_recvmsg.rs:166).

### CORRECTION — the epoll accept path is CORRECT; journald is stuck upstream

Chased the "epoll accept-strand" into the code + census and it does NOT hold up as
an epoll-wake bug:
- lib/src/readiness.rs `Readiness` is lost-wake-free by construction (set vs arm
  serialized under one lock).
- socket.rs connect (4109-4116) enqueues + `listener_readiness.set(POLL_IN,0)` +
  `.notify(POLL_IN)` on every pending.push_back.
- readiness_bits_for_state(UnixListener) RECONCILES the cell to `!pending.is_empty()`
  — level is correct.
- epoll.rs ET delivery (636-642) reports iff `new_bits(=ready&!last_mask)!=0` OR
  `listed(=cell_backed && in_ready)`. A `notify` lists the fd ⇒ ET reports it even at
  the same level. The path is CORRECT for a shared listener cell. DO NOT edit it.

The census disambiguates: journald (systemd-journal pid 9) is parked with
`scans=0 checks=0-2 epfd_enc=0 pnfds=0 netio=0` — NO epoll set up, barely scheduled:
it is STUCK EARLY IN STARTUP, before its accept loop. The journal/userdb listeners
are held only by PID1 (tid 16, socket-activation) waiting to hand off to the stuck
journald. So the pending connections are an UNREACHED acceptor, not a lost epoll wake.

⟹ REAL PATTERN: multiple daemons (journald pid 9; kwin) park early in an
UNCATEGORIZED blocking syscall (all PARKREP wait-fields 0, checks low/frozen) and
never progress — a lost wake in some blocking read/recvmsg/connect, NOT epoll/accept.
NEXT: add the parked-syscall-nr (+ blocking fd) to the census/park probe to name the
exact syscall journald/kwin strand in — that shared lost-wake is the true root. The
earlier "PID1 epoll accept-strand" framing below is SUPERSEDED by this.

### ROOT REFRAME (cachy_serial5.log) — kwin torn down externally [the "PID1 epoll ACCEPT-STRAND" part is RETRACTED — epoll audited correct; journald was an fs-park sampling artifact — see CORRECTION section above]

Errors-only syscall trace scoped to kwin (`trace_comm=kwin trace_errors_only` +
syscall-trace feature; boot rebased onto origin/main perf commits). Findings:

- kwin's ONLY traced errors are benign `readlink(...) = -22 EINVAL` on non-symlink
  path components (glibc realpath/canonicalize; Linux returns EINVAL too — CORRECT,
  not a bug). ⇒ kwin hits NO fatal syscall gap. Its death is EXTERNAL.
- This run kwin (pid 16 tid 213) was `killed_by_signal=15` (SIGTERM) FROM comm=systemd
  (the `[process-exit] kind=signal ... signal=15` + SIGSEND FROM systemd), only ~280
  log lines after exec — during Qt plugin loading, well before compositor init. Too
  fast for a 90 s start-timeout ⇒ a service stop/restart, not a ready-timeout.
  (Run 4 showed the twin: kwin exit_group(-1)/exit(15). Same root, timing-variant.)
- THE SYSTEMIC BUG the census caught alongside: PID1 (systemd, tid 16) is STRANDED in
  epoll_wait (epfd_enc=5) on its socket-activation listeners —
  `/run/systemd/journal/stdout` has n=13 PENDING unaccepted connections,
  `/run/systemd/userdb/io.systemd.Multiplexer` n=2 — with `scans=59` FROZEN across the
  whole 2 s window while `checks` climbs (13818→13856). A LOST EPOLL ACCEPT-WAKE: a new
  connection arrives on an epoll-watched AF_UNIX listener but never wakes the acceptor.
  Matches [[project_cachyos_greeter_epollet_fix]] ("socket-activation accept strand on
  PID1 listeners") and the epoll-wake class ([[project_unix_socket_poll_wake]],
  [[project_epoll_ctl_mod_rearm]], [[project_inet_dgram_wake]]). Earlier boots also
  showed epoll STRAND markers (fd cur!=last, "STRAND") in dbus-broker's epoll set.

⟹ NEXT TARGET: the epoll accept-strand — a connection landing on an AF_UNIX listener
that is watched edge-triggered via epoll must wake/re-arm the parked acceptor. This is
the highest-value root: it destabilizes session bring-up, so the greeter thrashes and
kwin is SIGTERM/restart-looped → black screen. Fix the lost listener-readiness epoll
wake, then re-verify the greeter stabilizes.

### EXIT REASON CAPTURED (cachy_serial4.log) — kwin exit_group(-1), VOLUNTARY

Widened the USEREXIT probes to fire under `unix-latency-trace` (not just the
cgevt_trace cmdline, whose cgroup-events flood froze an earlier boot at 38 s
before kwin). Run-2 config reached kwin, and the exit trace fired:

  USEREXIT comm=kwin_wayland.re exit_group_code=4294967295 (= -1/255)
           cg=.../user@957.../plasma-login-kwin_wayland.service
  USEREXIT comm=kwin_wayland.re exit_group_code=15
           cg=.../plasma-login-kwin_wayland.service

⟹ kwin (running as `plasma-login-kwin_wayland.service`) **exit_group()s ITSELF
with a FAILURE code** (-1/255, and once 15). NOT killed by a signal (no
killed_by_signal line, no SIGTERM/SIGABRT sender). `kwin_watchdog: Watchdog:
disabled … No WATCHDOG_USEC` ⇒ not a systemd watchdog kill either. So it is an
INTERNAL failure exit → systemd --user restarts the service → crash-loop → black
screen. Exit is SILENT (no error logged in kwin_err.log before it).

OPEN: WHY kwin exit_group(-1). The log shows the greeter QML UI loading
(KDEPlasmaPlatformTheme, QtQuick controls org.kde.desktop) each cycle before the
silent exit. Candidates: a failed syscall/ioctl kwin can't survive (kwin is in
LEGACY KMS — DRM_CLIENT_CAP_ATOMIC unimpl; DRM_IOCTL_MODE_LIST_LESSEES → ENOTTY),
or the greeter client failing and kwin propagating its code. NEXT: trace kwin's
LAST syscall before exit_group(-1) (add to the exit probe) to pin the failing
call. Boot is FLAKY (freezes 38 s / 144 s / reaches kwin ~75 s by serial load).

### kwin_err.log (full, 8159 lines) — kwin CRASH-LOOPS after full startup

Read the full greeter kwin_err.log (root loop-mount of the debug-copy, copied to
scratchpad). Overturns the "can't open card node" reading:

- kwin OPENS card0 fine and drives KMS: `kwin_wayland_drm: adding GPU
  /dev/dri/card0` → `New output on GPU /dev/dri/card0: Virtual-1-unknown`
  (connector id=3, Connected). The earlier `kwin_core: Failed to open drm node :
  No such file or directory` + `couldn't find dev node for drm device` are from
  the EGL probe path and are NON-FATAL — kwin recovers.
- kwin comes up FULLY each time: card0 output, libinput sees keyboard+mouse
  (event0-3), KGlobalAccel registers all shortcuts, KService rebuilds ksycoca.
- Then the ENTIRE kwin startup REPEATS — `New output on card0` and `kf.crash:
  Could not find drkonqi` each recur ~17× in the log. kwin CRASH-LOOPS: fully
  up → dies → respawn. NO SIGSEGV/abort/KCrash-"crashing" line ⇒ NOT a segfault;
  a clean exit or an external kill (SIGTERM/SIGKILL).
- Kernel-level confirmation (census run cachy_serial2.log): pid=16 is RECYCLED
  across tids 127→172→220, the earlier ones `st=2` (dead/zombie, comm cleared) —
  successive short-lived kwin instances.
- DRM ioctl gaps kwin hits (handled, but note for Linux-compare): drmModeListLessees
  → ENOTTY (DRM_IOCTL_MODE_LIST_LESSEES unimpl); drmSetClientCap(ATOMIC) fails →
  kwin falls back to LEGACY KMS; drmModeAddFB2WithModifiers unsupported → fallback.

⟹ Black screen = kwin never STAYS up. Leading hypothesis: kwin can't complete its
first PRESENT in legacy KMS (known present-stall, [[project_vt_layer_seat0_active_session]],
[[project_kwin_setcrtc_reqgate_reentrancy]]) so it never signals ready and the
greeter/systemd --user restarts it (Type=dbus never activates,
[[project_kwin_wedges_after_two_flips]]). NEEDS the exit reason to confirm.

INSTRUMENT (this session): widened the cgevt_trace USEREXIT probes (sys_exit_group.rs
voluntary exit_group_code; core.inc.rs signal killed_by_signal; compat.inc.rs the
SENDER of SIGTERM/SIGABRT) to also match comm kwin*/startplasma*/plasmalogin*.
Enable with cmdline `cgevt_trace` + feature `cgroup`. Boot cachy_serial3.log to
read: does kwin exit_group (clean/self-quit) or get killed, and by whom.

### CENSUS BOOT RESULT (2026-09-03) — kwin exits early; session live-locks on the dead compositor

Booted cachyos-debug-copy.raw headless (KVM, -cpu host, 8 GiB, virtio-gpu-pci,
XTASK_QEMU_SNAPSHOT=1 so the image is COW-protected) with
`--features stall-watchdog,unix-latency-trace`. NOTE: the park census
(`dbg_park_census`/PARKREP) lives inside `stall_wd::tick`, whose CALL site
(trap.rs:1322) is `#[cfg(stall-watchdog)]` — so BOTH features are required or
PARKREP never fires (a unix-latency-trace-only boot produced zero PARKREP).

Findings from PARKREP/PROCREP:
- The session REACHES the plasma-login greeter and launches kwin (greeter,
  kwin_wayland, startplasma-login, plasmalogin all present).
- **kwin_wayland (pid 16, tid 220) appears in the parked census EXACTLY ONCE**
  (checks=75, scans=0, ALL wait fields 0 — an uncategorized blocking syscall),
  right after `uevent-sock: created tid=220 comm=kwin_wayland.re replay=false`
  (kwin creating its udev/DRM-hotplug netlink monitor). It NEVER appears in any
  later PROCREP roster (roster fires ~30 s) ⇒ kwin existed only a few seconds,
  then exited/vanished. NO SIGSEGV/SIGABRT/fault on serial ⇒ the exit reason is
  in kwin's STDERR (the wrapper's /var/lib/plasmalogin/kwin_err.log), not serial.
- After kwin is gone: startplasma-login (pid 10) sits in poll(1 fd, no timeout),
  HEALTHILY re-polling (scans track checks with a fixed offset — NOT stranded) —
  waiting on the compositor that died. logind (pid 29) parks in
  waitid(pid=32, WEXITED) on a child (pid 32) that has no roster entry.
- No kernel panic, and STALL-WD never fired (no global syscall-progress stall):
  the desktop LIVE-LOCKS in userspace waiting on the dead kwin, it does not
  kernel-deadlock. (Matches memory: "kwin exits early, taking the session".)

OBSERVER EFFECT: the unix-latency-trace-ONLY boot (run 1) HARD-froze at ~144 s
(total serial silence, no census — because PARKREP needs stall-watchdog too);
the both-features boot (run 2) did NOT hard-freeze, it live-locked. The stall-wd
per-tick RIP recording changes timing. Treat the hard-freeze-at-144s as a
possibly-separate manifestation.

TWO REAL ERRNO BUGS surfaced right before kwin's exit (session/VT handover):
- systemd-logind evdev revoke → EFAULT ("Bad address"). No EVIOCREVOKE handler
  exists (grep) ⇒ the integer arg 0 is likely copied as a user pointer → EFAULT.
  Linux EVIOCREVOKE takes an int (0), returns 0. Fix: handle EVIOCREVOKE (revoke
  or no-op success), never EFAULT.
- systemd-logind "Failed to restore VT, ignoring: Operation not supported"
  (ENOTSUP) — a VT op logind uses on session restore that the new vt.rs layer
  doesn't implement. Non-fatal ("ignoring") but part of the handover.

NEXT: get kwin's exit reason from kwin_err.log (needs root loop-mount of the
image — sudo password — OR a persist/non-snapshot boot OR user paste). Then fix
the actual kwin-exit cause. The evdev EVIOCREVOKE→EFAULT and VT-restore→ENOTSUP
are independently fixable errno/impl bugs.

### THIRD blocker — SECOND COURSE CORRECTION: block-layer theory REFUTED; kwin parks elsewhere

Deeper reading of the actual code refutes the whole block-layer stall model
(mine AND the summary's). Three independent refutations:

1. `responsive_spin_until` (scheduler/src/lib.rs:5113) is a PURE BUSY-SPIN
   (sleep_pumps every 4096 iters; NEVER halts, NEVER context-switches to another
   user task). A task in a root-fs read busy-spins at 100% CPU — its RIP samples
   INSIDE responsive_spin_until, NOT idle_halt. The observed idle_halt therefore
   means kwin was NOT in a block read at the sample instant.
2. `SyncBlock::submit` (block/src/registry.rs:272) runs `do_io` SYNCHRONOUSLY
   before returning the future, so `poll_blocking(ops.read())` completes on the
   FIRST poll after the spin — it never parks holding the scratch lock. The
   "parks holding VolumeIo scratch lock" model is wrong.
3. `req_gate` (blk_pci.rs:1377) already serialises to ONE in-flight request and
   COOPERATIVELY YIELDS on contention (spin 128× then cooperative_yield). So
   completion-stealing can't arise (one request in flight) and the gate doesn't
   hard-deadlock.

Also: the async IRQ-driven blk path (blk.rs `VirtioBlkDevice`) is virtio-MMIO
(`mmio: VirtioMmioDevice`) and nothing constructs it for the PCI root disk.
"Switch root to async" = add MSI-X async submission to `VirtioBlkPci` — a large,
risky change — NOT a swap. Not doing it on a disproven theory.

⟹ idle_halt = the system is waiting on an event that never comes (a LOST WAKE);
kwin is PARKED on something (epoll fd / futex / poll / sleep / waitpid), not in
the block layer. Need ground truth on the park site before any fix.

GROUND-TRUTH INSTRUMENT (already in-tree, now completed): `dbg_park_census("")`
(userspace/task.rs:420, feature `unix-latency-trace`) fires every ~10 s from the
timer trap AHEAD of the DUMPED gate and prints, per parked task: comm, scans
(dbg_poll_scans — frozen+parked = stranded/lost-wake; climbing = healthy idle),
epoll_wait_fd, poll_wait_nfds, futex, sleep deadline, waitpid. PROCREP roster +
PROFTOP profiler fire on slower cadences. ADDED (trap.rs): a `PARKBLK` line in
that same ahead-of-gate sweep printing `stalled_queue_snapshot()` so ONE boot
also says whether a virtio-blk request is genuinely stuck >1 s. Compiles under
`--features unix-latency-trace`.

DECISIVE EXPERIMENT: boot CachyOS with `--features unix-latency-trace`, let it
reach the freeze, capture serial. Read the PARKREP line for the kwin tid: the
park-site field that's set + whether `scans` is frozen across successive reports
pinpoints the lost wake. Fix THAT site (not a guess). PARKBLK present ⇒ disk is
actually stuck (revisit block); PARKBLK absent ⇒ block is idle, not the cause.

### THIRD blocker — (earlier, now superseded) root fs reads are SYNC busy-poll, IRQ-drain is the WRONG fix

Followed the block-device adapter and it overturns the IRQ-drain plan. The ext4
root (vblk0) is registered as a `BlockDeviceSync` and wrapped in `SyncBlock`
(block/src/registry.rs:253) to satisfy ext2's `BlockDevice` (async) bound. But
`SyncBlock::submit` (registry.rs:272) runs the I/O SYNCHRONOUSLY —
`self.do_io(&req, buffer)` executes BEFORE the async block; the future just
wraps the finished result. `do_io` → `VirtioBlkBlockSync` (blk_pci.rs) →
`responsive_spin_until` (BUSY-POLL). So the root's file reads BUSY-POLL the
used-ring; they do NOT await the completion IRQ. `blk_irq_noop` (blk.rs) is only
on the ASYNC `VirtioBlkDevice` path, which the root fs does NOT use.

⟹ Making the block IRQ drain the used-ring would NOT fix this stall (wrong path),
and changing a block-driver IRQ on an unused path is pure risk. The real fix is
option (b): the read holds the `VolumeIo` scratch lock (acquire_scratch,
volume.rs:191) across `do_io`'s busy-poll round-trip — the exact
scheduler_step_pump / [[project_plasma_black_screen]] shape ("polled sync I/O
holds its driver lock; a nested task spins on it"). Fix: don't hold the VolumeIo
scratch lock across the block round-trip, and/or resolve the busy-poll that
deschedules while holding the lock. Still OPEN: idle-vs-spin not fully resolved
(RIP idle_halt despite a busy-poll path) — a task descheduled mid-busy-poll
holding the lock is the leading theory; needs confirming before the fix.

### THIRD blocker — ROOT MECHANISM found: block completion not drained when idle

Completion instrumentation traced it to the root. kwin parks in `sys_read`'s
`poll_blocking(endpoint.ops.read())` (probes KRD-A/KRD-B proved it parks AT the
read, AFTER acquiring the per-description position_lock, never at the lock). It
parks FOREVER despite the async block device's 5s deadline — so the park is a
NO-DEADLINE wait in the fs/block layer, not the deadline'd device wait itself.

The chain (drivers/fs/ext2/volume.rs + drivers/virtio/blk.rs +
frame/bare_main.rs):
- A file read holds the VolumeIo scratch lock (acquire_scratch, volume.rs:191)
  across `device.submit(req).await` (volume.rs:416) — "lock held across the whole
  device round-trip", the exact [[project_plasma_black_screen]] shape but for
  the VolumeIo scratch lock (the ReqGate only fixed the CONTROLLER lock).
- The async `BlkRequestFuture::poll` (blk.rs:598) registers a waker + Pending
  until `device.poll()` drains the used ring and fires `req.waker.wake()`
  (blk.rs:362). The block IRQ handler `blk_irq_noop` (blk.rs:431) is a NO-OP —
  it does NOT drain. So the completion is drained only by a pump
  (sleep_pumps/scheduler_step_pump).
- bare_main.rs:4501 `scheduler_step_pump` documents it: "Polled sync I/O calls
  sleep_pumps::run() while holding its driver lock; a nested user task can enter
  the same driver and spin forever on that lock (observed during startplasma
  DSO fault-in)." So when the system idles waiting on one block read, the
  completion isn't drained → the read future stays Pending → the VolumeIo lock
  is held forever → EVERY volume read deadlocks (kwin idle, RIP idle_halt).
  Intermittent because it needs the system to fully idle on a not-yet-drained
  completion.

FIX DIRECTION (delicate driver/scheduler — NOT rushed): (a) make the virtio-blk
completion IRQ drain the used ring + wake the per-request waker instead of the
no-op `blk_irq_noop` (so a completion wakes the reader without a pump), and/or
(b) don't hold the VolumeIo scratch lock across `device.submit().await`, and/or
(c) ensure the block completion pump runs when the system is otherwise idle.
Confirm lost-wakeup vs stuck-IO by counting used-ring completions vs submits
while kwin is parked.

### (earlier) THIRD blocker — LOCATED: block-read async park/wake (present-stall, open)

Dug the third blocker to its precise location. A scoped KREAD probe (kwin reads
only, capped) showed the parking read is `read(fd, blocking, ~0x4000)` on a
`type=File`, `is_stream=false`, `poll_readiness=readable` (files always read as
ready). So it's a BLOCKING FILE read that parks in `sys_read`'s
`poll_blocking(ops.read())` — the ext4 page-cache read future returns Pending
(page not cached → block read), the task parks, and the completion never wakes
it. Key facts:
- INTERMITTENT: hundreds of file reads complete first; the parking fd varies
  (0x25 on SMP=16, 0x23 on SMP=1) — it's "whatever file read is in flight," not
  a specific file.
- SMP=1 ALSO parks (KREAD stable, RIP idle_halt) → NOT core contention, and NOT
  the busy livelock (which spins) — it's a genuine park.
- So: a lost-wakeup-class bug (completion fires the waker in the poll→park
  window, or never fires) in the block-read async path
  (poll_blocking → park_pending_future → yield_current_stackful vs the
  virtio-blk completion waker), OR the block IO genuinely never completes.

This is the SAME subsystem as the documented [[project_plasma_black_screen]]
"lock held across the whole device round-trip" livelock — drivers/storage +
drivers/virtio req_gate.rs (whose module docs say the ReqGate REPLACED holding
the controller spinlock across I/O to fix that livelock). The async park/wake on
top may have a residual missed-wakeup.

NEXT (a focused, careful effort — block-layer/scheduler is high-risk):
1. Instrument the ext4/virtio-blk block-read completion → wake to decide
   lost-wakeup (completion arrives, wake lost) vs stuck-IO (completion never
   arrives) — count completions while kwin is parked.
2. If lost-wakeup: park_pending_future/yield_current_stackful must re-check a
   pending-wake flag set by the completion waker before parking.
3. If stuck-IO: the virtio-blk request/completion (req_gate, used-ring drain)
   for that read is dropped/never rung.

Confirmed NOT the fix target: sys_read's position_lock (line 141, held across
the file read) is per-description; the completion path doesn't need it, so it
amplifies impact (blocks other readers of the same fd) but isn't the root.

### (superseded) earlier THIRD-blocker note:

After fix #2 kwin parks on `read(fd=37, nb=false /* BLOCKING */, 0x4000)` — it
drains a stream in 0x4000 chunks then blocks for more. A BLOCKING read whose
data never arrives: likely a file/disk read whose virtio-blk completion is
missed, or the documented [[project_plasma_black_screen]] virtio-blk livelock
(though RIP showed idle_halt = parked, not the busy livelock — so a missed
completion wakeup, not a spin). Guest still idle, no SETCRTC/scanout. NEXT:
identify fd 37 (a blocking read — a file being loaded? a helper pipe?) and why
its data/completion never wakes kwin. Diagnostic: the scoped KPARK probe
(removed) — re-add to syscall.rs dispatch to find the next parking fd.

## 2026-09-03 VT layer LANDED (branch feat/vt-layer-seat0, commit 645295d7)

Committed the VT layer + chown fix + 5 filesystem/vt smoke tests. CI gates run
locally green: fmt, clippy (x86_64 + aarch64, kernel-test feature), the 5 VT
tests (5 pass/0 fail), boot-smoke clean. cachy.md deliberately untracked.

### Part 2 (present-stall) — characterized, NOT yet fixed

With the VT layer, kwin comes up fully: EGL, `adding GPU /dev/dri/card0`, `New
output ... Virtual-1`, libinput keyboard — then goes IDLE with NO scanout
(screendump vgpu0 = "no surface"). RIP sample: 96/96 idle_halt (guest idle, not
spinning; the ~283% qemu is KVM halt-poll). So kwin parks in its event loop
BEFORE the first modeset (SETCRTC) — a missed first-paint trigger, earlier than
the pageflip path (NARF's handle_page_flip DOES queue the completion event via
card.queue_flip_event — drm_ioctl_bridge.rs:1650 — so that's not the gap).

Diagnostic note: a full `trace_comm=kwin` syscall trace is too slow here
(observer effect: ~1700 syscalls in 3+ min, still mid-init) to reach the block.
NEXT for Part 2: a targeted NARF probe that prints kwin's blocking syscall +
which fds it polls when it parks (get-data-first), or examine kwin's RenderLoop
first-paint scheduling / whether it waits on a vblank/present-timing source NARF
doesn't provide, or the greeter-UI client's first frame. This is a compositor
render-loop / DRM present-timing frontier, separate from the active-session fix.

## 2026-09-03 FIX BUILT: minimal VT layer — card0 now opens (TakeDevice works)

Built the correct long-term fix (#3): a minimal logical VT layer so seat0's
active-session tracking works and logind hands the compositor DRM fds via
TakeDevice. Files:
- `filesystem/src/vt.rs` (new) — global active-VT + allocation + per-VT mode.
- `filesystem/src/devfs_pty.rs` — VT_SETMODE/VT_RELDISP/KDSETMODE consts +
  vt_stat/vt_mode user read/write helpers.
- `filesystem/src/devfs.rs` — DevConsole::ioctl implements VT_OPENQRY /
  VT_GETSTATE / VT_ACTIVATE / VT_WAITACTIVE / VT_GETMODE / VT_SETMODE /
  VT_RELDISP / KDSETMODE against `crate::vt`; `/dev/ttyN` lookup for N..=63.
- `filesystem/src/sysfs.rs` + `frame/src/bare_main.rs` — populate_tty_class()
  registers `/sys/class/tty/tty0/active` (reads vt::active_sysfs()), wired as a
  Stage::Late initcall "sysfs-tty-class".

BOOT-VERIFIED on the copy: the "not /sys/class/tty/tty0/active which is broken"
warning is GONE; logind engages VT management; **kwin now opens /dev/dri/card0**
(`kwin_wayland_drm: drmSetClientCap ... on GPU "/dev/dri/card0"`,
`drmModeListLessees()` — both are ioctls on an OPEN card0 fd). plasma builds its
sycoca cache. The active-session/card0/TakeDevice root blocker is RESOLVED.

### UPDATE — with the chown fix (DevConsole set_owners), kwin's whole stack comes up

Boot-verified clean run (per-run log, chown warnings GONE): kwin now reaches —
`Egl Initialize succeeded` → `adding GPU /dev/dri/card0` → `New output on GPU
/dev/dri/card0: Virtual-1` (connector Connected) → `Libinput: event0 device is a
keyboard`. So **GPU + output + input all come up**, and the earlier "Failed to
take control (another compositor)" + input EPERM were CRASH-LOOP ARTIFACTS from
the appended err log (gone in a clean run). The VT-layer + chown fix take the
desktop stack from "black at logind" all the way to a live compositor with an
output and working input.

REMAINING: no first frame yet. kwin creates the output then goes IDLE (RIP
sample: 96/96 `idle_halt_then_disable` — the ~283% qemu is KVM halt-poll, guest
is idle, NOT the virtio-blk livelock and NOT a busy-loop). So it's a
MISSED-WAKEUP at the present step — most likely DRM pageflip-complete event
delivery (legacy KMS drmModePageFlip → waits for DRM_EVENT_FLIP_COMPLETE on the
card fd) or waiting for the greeter UI client's first frame. That is a separate,
downstream DRM/present frontier, not the active-session fix.

Non-fatal along the way: atomic modeset unsupported → legacy KMS;
drmModeAddFB2WithModifiers unsupported; drmModeListLessees ENOTTY; no EDID on
Virtual-1 (kwin uses a default mode).

### Older (pre-chown-fix) note — some were crash-loop artifacts:
- `kwin_core: Failed to take control of .../session/c1 (Maybe another compositor
  is running?)` — logind TakeControl.
- `kwin_libinput: opening input device /dev/input/eventN failed (Operation not
  permitted)` — input's TakeDevice/seat path (the input analog of card0).
- `drmSetClientCap ATOMIC failed → legacy mode` + `drmModeListLessees()
  Inappropriate ioctl` — non-fatal; kwin falls back to legacy KMS.
- `Cannot change owner of /dev/tty1` + `Failed to restore VT` — ENOTSUP; both
  from console `chown` (DevConsole lacks set_owners). Fixing next.

## 2026-09-03 ROOT CAUSE: logind can't find the active graphical session (no /sys/class/tty/tty0/active)

Chased the card0 EACCES to its true origin. It is NOT the file DAC:
- Added a scoped diagnostic at the open() DAC check (posix_access_ok_with_acl,
  core.inc.rs ~1502) that prints owner/mode/accessor/groups/acl on any dri/card
  denial. On the greeter boot it NEVER FIRED → the NARF file-permission check
  does NOT deny card0. (Diagnostic reverted.)
- So the "Permission denied" is post-DAC. Commit aa8dc445's own message spells
  out the mechanism exactly: "kwin opens O_RDWR, and when logind cannot hand it
  an fd ('Could not determine the active graphical session') that direct open is
  the only path it has — then it reports 'Failed to open drm device
  /dev/dri/card0', finds no suitable DRM device and exits, taking startplasma
  and ksmserver (SIGABRT)."

The chain: (1) kwin asks **logind TakeDevice** for card0 (logind opens it as
root — the correct path, seen in the trace: logind opens card0 several times).
(2) logind **refuses — "Could not determine the active graphical session"** —
it doesn't consider the greeter session ACTIVE on seat0, so it won't hand out
DRM fds. (3) kwin falls back to a direct O_RDWR open → fails (plasmalogin uid
957 has no direct card0 access; it's not in `video` — only `narf`/1000 is — and
NARF applies no uaccess ACL; logind emits ZERO setxattr).

**The concrete NARF gap:** logind logs `System has /dev/tty0 but not
/sys/class/tty/tty0/active which is broken, ignoring: No such file or
directory`. NARF's sysfs has `/sys/class/tty/ttyUSB*/` but **no
`/sys/class/tty/tty0/active`** and no active-VT/seat tracking. That file (holds
the active VT, e.g. `tty1`) is how logind maps active-VT → the session's VTNr →
marks it active on seat0. Missing → no active session → TakeDevice denied.

**FIX DIRECTION (the real NARF fix, not the ACL layer):** expose
`/sys/class/tty/tty0/active` (+ likely `/sys/class/tty/tty0/` kobject) reporting
the active VT that matches the greeter session's VTNr, and wire whatever
active-VT tracking logind reads, so logind marks the greeter session active on
seat0 and TakeDevice hands kwin the card0 fd. NOT the ACL/video-group path
(logind never applies an ACL here, and stock images don't put the greeter user
in video — they rely on TakeDevice). Confounds proven false along the way: QPA
"crash" was the wrapper's `.real` rename (KWIN_FORCE_OWN_QPA fixes it — QPA now
loads: "Successfully loaded Qt platform plugin wayland-org.kde.kwin.qpa"); card0
EACCES is NOT the file DAC.

## 2026-09-03 kwin REAL blocker: EACCES on /dev/dri/card0

The QPA "crash" (below) was a WRAPPER ARTIFACT — my debug wrapper renamed
kwin_wayland → kwin_wayland.real, and KWin's QPA `create()` gates on the exe
path ending in "kwin_wayland" (or `KWIN_FORCE_OWN_QPA` set); the `.real` name
tripped it (invent.kde.org src/plugins/qpa/main.cpp). Classic "diagnostic
changes the failure". Fix: `KWIN_FORCE_OWN_QPA=1` in the wrapper.

With that set, kwin runs its REAL backend init and the genuine failure appears
(full `*=true` capture):

    kwin_scene_opengl: Egl Initialize succeeded / EGL version: 1.5
    kwin_core: Added render device /dev/dri/renderD128           (render node OK, 0666)
    default: No backend specified, automatically choosing drm
    kwin_core: Failed to open drm node /dev/dri/card0: Permission denied   ★ EACCES
    kwin_wayland_drm: No suitable DRM devices have been found

So EGL/GL/renderD128 all work; kwin dies because the PRIMARY/KMS node
**/dev/dri/card0 returns EACCES** → no modeset device → no scanout → black. This
is the exact symptom of [[project_supplementary_groups_dac]] ("kwin EACCES on
/dev/dri/card0"), whose fix (honour supplementary groups in POSIX access —
a5de0e94/2dfe47db) IS in main. card0 is devtmpfs 0o600, udev raises it to
root:video 0o660 (drm_devfs_bridge.rs:57). So EACCES means plasmalogin isn't
getting card0 access — either not in the `video` group, card0 not group=video
after udev, or NARF isn't applying the logind uaccess ACL / kwin isn't using
logind TakeDevice. NEXT: confirm plasmalogin's groups + card0's post-udev
group/mode; that picks the fix direction (group membership vs device ACL vs
TakeDevice fd-passing).

## 2026-09-03 kwin "hang" is actually a CRASH — QPA plugin load failure (WRAPPER ARTIFACT, see above)

Cracked the kwin no-present. It is NOT a hang — kwin_wayland **aborts (SIGABRT)**.
Method: RIP-sampled the busy guest via QMP → 89/96 samples were
`idle_halt_then_disable` (scheduler idle), so the guest is IDLE, not spinning
(the ~360% qemu CPU is KVM halt-poll). So kwin is blocked/dead, not looping.
Then a tight `trace_comm=kwin` syscall trace (copy, SMP=1) caught the end:
after loading the Qt platform plugins, kwin does `gettid`/`getpid`/`tgkill(self,
self, sig=6=SIGABRT)` — a one-shot `abort()`, right after 3 `sendmsg`s to the
journal socket (fd 3). NOT a crash loop.

Captured the fatal message (wrapper forced Qt logging to a persistent file,
QT_FORCE_STDERR_LOGGING=1, boot NON-snapshot, then loop-mount + cat):

    qt.qpa.plugin: Could not load the Qt platform plugin
      "wayland-org.kde.kwin.qpa" in "" even though it was found.
    This application failed to start because no Qt platform plugin could be
    initialized. Reinstalling the application may fix this problem.
    Available platform plugins are: eglfs, linuxfb, minimal, minimalegl,
    offscreen, vkkhrdisplay, vnc, wayland-brcm, wayland-egl, wayland, xcb,
    wayland-org.kde.kwin.qpa.

So KWin's OWN QPA plugin (`wayland-org.kde.kwin.qpa`) is FOUND but fails to
load/initialize → Qt has no platform → abort. "even though it was found" = the
.so loads but `create()` returns null (or a dlopen dependency is unresolved).
That plugin's init is where KWin brings up its DRM/EGL/Wayland backend, so the
failure is inside that backend init on NARF. Args the greeter passes:
`--no-lockscreen --no-global-shortcuts --no-kactivities --inputmethod
plasma-keyboard --locale1`.

NEXT: re-capture with `QT_DEBUG_PLUGINS=1` (+ EGL/Mesa debug) to get the exact
dlopen/symbol error or the create()-returned-null reason — that names the NARF
gap (a GPU/DRM ioctl, an EGL/GBM call, or an unresolved symbol).

Capture tooling: scratchpad/kwin_capture.sh {install|read} (loop-mounts the COPY
at offset 4256169984 / p2, installs a kwin_wayland wrapper, reads
/var/lib/plasmalogin/kwin_err.log). journald forward_to_console does NOT forward
user-session journal entries, and kwin logs via the journal socket not stderr —
hence QT_FORCE_STDERR_LOGGING + a file, not console capture.

## 2026-09-02 kwin hang — characterized (on drm-master-arbitration + mknodat fix)

Traced `kwin_wayland` (SMP=1, clean). Findings:
- kwin launches, connects to the SESSION bus (QDBusConnection), then loads KDE
  config: `/var/lib/plasmalogin/.config/kdeglobals` (openat→mmap→read-to-EOF→
  munmap→close), then `statx` probes for `kwin_waylandrc` across the xdg dirs
  (`/var/lib/plasmalogin/.config`, `/etc/xdg`, `kdedefaults`) — several ENOENT.
- Then kwin STOPS making syscalls entirely (flat SYSC count) and does NOT crash
  (no fatal-fault, no process-exit). Its last syscall is a COMPLETED `statx`,
  so it is NOT blocked in a syscall — it is idle/waiting in userspace, BEFORE
  the GPU/wayland backend init (no poll/ppoll/epoll ever — never reaches the
  event loop). screendump vgpu0 = "no surface" (never SET_SCANOUT).
- The guest vCPU is PEGGED (~115-131% qemu) — but by something OTHER than kwin
  (kwin's trace is flat). QMP `info registers` RIP samples are mostly KERNEL
  (`syscall_entry_x86_64` recurring, plus scheduler/`Weak::drop`/`slice
  position`/`narf_arch_cpu_id`) with occasional userspace `0x40900…`. So a
  non-kwin process is syscall-looping, or the kernel is busy-looping, while kwin
  waits.
- RULED OUT: it is NOT the unmasked network stack. Re-masking avahi/resolved/NM
  did NOT change the CPU peg (still ~131%) or the black screen. (Avahi had been
  restart-looping in the log, which looked like the hog, but masking it proved
  it wasn't.)

So the desktop gate is now: (1) kwin idles in userspace after config, before
backend init; (2) a separate busy-loop pegs the CPU regardless of the network
services. Both are downstream of everything the mknodat fix unblocks and are the
drm-master-arbitration branch's own compositor/greeter/scheduler bringup work.
NEXT: identify the busy-looping comm (a broad trace or a running-task/comm
sampler, since masking services didn't find it), and get kwin's OWN debug output
(QT_LOGGING_RULES / KWIN debug env via the greeter session) to see what it waits
for after config — syscall tracing alone can't see a userspace wait.

## 2026-09-02 ROOT CAUSE FOUND: `ProtectKernelLogs=yes` is THE blocker

Via clean systematic bisection (minimal `Type=oneshot ExecStart=/usr/bin/true`
test units on the CachyOS image, added with debugfs): a unit carrying logind's
FULL sandbox fails; each directive tested alone passes; splitting the set, the
**mount/Protect\* stack** fails (not seccomp); splitting that, the culprit is a
SINGLE directive: **`ProtectKernelLogs=yes`**. A unit with ONLY
`ProtectKernelLogs=yes` fails (captest-t). RULED OUT (all pass alone AND in
sub-stacks): CapabilityBoundingSet, DeviceAllow, IPAddressDeny,
RestrictAddressFamilies, SystemCallFilter/@system-service, MDWE, LockPersonality,
RestrictNamespaces, NoNewPrivileges, PrivateTmp, ProtectHome,
ProtectControlGroups, ProtectSystem=strict (mounts fine!), ProtectKernelModules.

**Why this is THE answer:** `systemd-logind`, `NetworkManager`
(`ProtectKernelLogs=true`) and `systemd-resolved` (`ProtectKernelLogs=yes`) ALL
set it — exactly the three services that fail-loop and block the seat/desktop.
Also proven: the logind BINARY execs fine (captest-f `Type=exec` on the real
`/usr/lib/systemd/systemd-logind` → Started), so it's not the binary/notify/deps.

**Mechanism (systemd main src/core/namespace.c, via WebFetch):**
`ProtectKernelLogs` overmounts an INACCESSIBLE node onto `/proc/kmsg`
(ignore_enoent) and `/dev/kmsg` (ignore_enoent) —
`mount(/run/systemd/inaccessible/chr, /dev/kmsg, MS_BIND)`. The `ignore` flag
covers only a MISSING TARGET, not a mount failure. NARF facts: (a) NO
`/proc/kmsg` node in procfs (only the `kernel/printk_devkmsg` sysctl); (b)
`/dev/kmsg` EXISTS (devfs.rs `DevKmsg`); (c) `sys_mknodat` makes ALL non-dir
nodes — incl `/run/systemd/inaccessible/chr` — REGULAR FILES ("no character node
types"); (d) `ProtectSystem=strict` (also mounts) PASSES → general mount-ns
machinery works; it's kmsg-specific.

**NOT yet root-caused to the syscall.** The captest-t executor makes NO erroring
syscall and NO traceable mount/unshare (systemd 261 uses the new mount API —
open_tree/move_mount/fsopen/fsmount/mount_setattr — which NARF's syscall-trace
doesn't surface under comm=systemd-executo; ProtectSystem=strict proves they
otherwise work). So it's the `/dev/kmsg` overmount via the new API, or a wrong
result on the missing `/proc/kmsg` (lstat not clean ENOENT so systemd won't skip).

**FIX DIRECTION:** 1) add a `/proc/kmsg` node to NARF procfs (cheap; boot
captest-t — rules the /proc/kmsg leg in/out); 2) verify NARF's new-mount-API path
(open_tree/move_mount) for overmounting a devfs node (`/dev/kmsg`) with a
regular-file source; 3) confirm errno correctness on the missing-node lstat.
Reproduce fast with a ONE-directive `ProtectKernelLogs=yes` oneshot unit on the
debug copy — fails in ~1 boot, no logind needed. captest-* test units + the
`ananicy-cpp`/`systemd-resolved`/`NetworkManager`/`avahi` masks currently live on
`/home/daniel/vms/cachyos-debug-copy.raw` (throwaway).

**Superseded lead:** systemd spawns every service with
`clone3(CLONE_INTO_CGROUP, cgroup_fd=N)` (seen as `[CLONE3 flags=0x300005100
… cgroup_fd=NN]` in a broad `trace_comm=systemd` trace). logind uses cgroup
DELEGATION. A bug in NARF's `clone3` CLONE_INTO_CGROUP path (or cgroup
delegation) specific to logind's spawn would make it fail fast, pre-exec, with
no logind syscalls — matching every observation — while simpler services
(dbus/avahi) that don't delegate succeed. Chase clone3+CLONE_INTO_CGROUP and
cgroup delegation for the logind unit next. All comm-filtered traces flood
(PID1's comm is `systemd`); need a targeted clone3-return probe, not a full
trace.

**SECONDARY (cosmetic) — `ananicy-cpp` SIGSEGV crash-loop.** The repeated
`fatal-fault: comm=ananicy-cpp sig=11 #PF faultva=10 rip=80000668b6` dumps on
the console are a USERSPACE fault, not a kernel panic. Disassembled from the
image: the RIP is ananicy-cpp's own fatal-error stub in `ProcessQueue::init()`
(`mov rax,[0x10]; ud2`), reached because **`bpf_object__open_skeleton()`
returned an error** → prints "failed to open BPF object" → traps. ananicy-cpp
is an eBPF daemon; NARF's BPF/BTF support isn't enough for libbpf to open its
skeleton, so it dies. It is a NON-ESSENTIAL auto-nice daemon — does not block
the desktop — but "we shouldn't segfault on a normal Linux install" stands: it's
a real NARF BPF gap. Extract + disassemble recipe (no boot needed):
`debugfs -R "dump /usr/bin/ananicy-cpp /tmp/a" "cachyos-fresh.raw?offset=$((8312832*512))"`
then `objdump -d --start-address=0x66760 --stop-address=0x668c0 /tmp/a`.

**Wrong-errno cluster to audit (the class dhodges flagged).** These units all
`[FAILED]` with `code=exited, status=1` on `main` and are prime suspects for a
syscall returning the wrong errno vs Linux (each does a handful of syscalls then
exits 1): `systemd-vconsole-setup`, `systemd-remount-fs`, `systemd-sysusers`
(Create System Users), `systemd-resolved` (fail-looped 6×), `systemd-update-utmp`
(UTMP), journal-catalog rebuild, `ldconfig` (Rebuild Dynamic Linker Cache),
`nftables` (CLI Netfilter Manager). Also seen at mount probe:
`Unable to determine whether tmpfs supports 'usrquota' … Resource temporarily
unavailable` (EAGAIN from a mount/statfs probe where Linux would not return
EAGAIN). Trace each with `trace_comm=<comm> trace_errors_only` and diff the
errno against `~/git/linux`.

---

## 2026-08-16 SESSION UPDATE — the CachyOS greeter blocker is the SESSION bus, not the system bus

Focus: the CachyOS Plasma **greeter** stall (plasmalogin → startplasma-login-wayland),
distinct from the Fedora udev gate below. Branch `cachyos-efi`, HEAD `98058aab`.

### 6 commits landed (all real, RED→GREEN tested)
- `00ef83f9` epoll: don't consume an EPOLLET edge on an undelivered scan
- `af64421b` epoll: re-arm edge state on EPOLL_CTL_MOD (Linux re-evaluates readiness on MOD)
- `f19d32d8` epoll: strand census → finite parks + throttle (diagnostic, silent-unless-strand)
- `84444898` net: AF_INET (UDP) datagram delivery must call readiness::notify (lost-wake; UDP loopback = resolved/avahi — latency fix)
- `eca2e90c` diag: decode D-Bus method calls under syscall-trace (`socket::dbg_dbus_peek`, TX/RX on sendmsg/recvmsg)
- `98058aab` futex: TWO lost-wake bugs — (1) ghost-waiter leak: a timed-out/signal-broken FUTEX_WAIT never called `futex_drop_waiter_key`, so a later FUTEX_WAKE(1) pops a dead "ghost", wakes nobody real, and force-clears an unrelated park; (2) CLEARTID exit wake fired PRIVATE, but Linux mm_release wakes SHARED (no FUTEX_PRIVATE_FLAG) and glibc pthread_join waits SHARED. Both RED→GREEN, 61 pass. (Your futex instinct — correct.)

### THE KEY REDIRECT: I was tracing the WRONG BUS the entire session
Reading the source (plasma-login-manager / plasma-workspace `startplasma.cpp`) settled it.
`startplasma-login-wayland` does NOT launch kwin directly. `startPlasmaSession()` does:
1. `locale1` GetAll on the **SYSTEM** bus  ← the ONLY thing my traces ever saw
2. runEnvironmentScripts / setupPlasmaEnvironment (config dir, KDE_FULL_SESSION, theme)
3. **`importSystemdEnvrionment()`** — D-Bus to **systemd --user**
4. **`syncDBusEnvironment()` → `KUpdateLaunchEnvironmentJob`** — `UpdateActivationEnvironment` on the **SESSION** bus + `SetEnvironment` on systemd --user
5. **`StartUnit("plasma-login-wayland.target","fail")` via `QDBusConnection::sessionBus().call()`** — a BLOCKING **session-bus** call; the login variant pulls in **`plasma-login-kwin_wayland.service`** (kwin as a systemd SERVICE, not a direct exec)
6. then blocks in `e.exec()` until `org.kde.KWinWrapper`/`org.kde.Shutdown` unregister

Every D-Bus trace this session watched ONLY the SYSTEM bus (dbus-broker). Steps 3–5 —
where the greeter actually blocks — are on the SESSION bus / systemd --user, a socket I
never observed. That is why every trace showed "all system-bus D-Bus completes" and then
main idling on its dispatcher eventfd: it is blocked in a synchronous `sessionBus().call()`
to systemd --user that never returns. Lines up with the known "plasma-* user units never
start (inactive, not failed)" pattern (memory: project_fedora_kde_bringup,
project_systemd_user_cgroup_delegation).

### Two FALSE ALARMS cleared this session — do NOT re-chase
- **cgroup is present.** `systemd-pid1` AUTO-INJECTS `cgroup-all`+`boot-init`+`firmware-allow-unsigned` (build/xtask/src/main.rs:2360 `ensure_feature`). So `--features container` boots ARE cgroup-complete (`cgroup2 mounted at /mnt/sys/fs/cgroup` confirmed). NOT a feature-incomplete/incompatible kernel.
- **virgl does NOT wedge.** The old "virgl wedges" note is STALE (predated `e65cc177`). `--display gtk --gpu-backend virgl` (host DISPLAY=:0 + QEMU virtio-gpu-gl-pci,id=vgpu0) boots CLEAN, no GL/virgl init errors; guest GL is available. Greeter still stalls (QMP `screendump` = "no surface" — compositor never `SET_SCANOUT`), but that is the SAME session-bus stall, independent of GL.

### Greeter stall — what it is NOT (ruled out this session)
- NOT a system-bus wake bug (all system-bus D-Bus completes; the `locale1 NameHasNoOwner` is benign/answered).
- NOT epoll edge / fork socket-clone / sd_notify DGRAM (audited clean by subagents).
- NOT the futex ghost bug — VERIFIED identical greeter stall WITH and WITHOUT `98058aab` (same D-Bus trace, same `locale1` stop point). The ghost bug is LATENCY-only: the 10 ms park backstop always re-scans infinite parks, so it cannot cause a minutes-long stall.
- NOT missing cgroup, NOT a virgl wedge.

### NEXT (correct target): the SESSION bus / systemd --user
Trace/inspect the greeter's SESSION-bus + systemd --user path (NOT the system bus). Is
systemd --user running for the plasmalogin user? Does the session bus exist? Does
`StartUnit(plasma-login-wayland.target)` return or hang, and do the plasma-login-* units
start? Point `dbg_dbus_peek` (eca2e90c) at the greeter's SESSION-bus fd (a DIFFERENT fd
from the system-bus one) — it decodes any AF_UNIX stream.

### Reproduce the greeter (GTK so it's visible; host has DISPLAY=:0)
```
env NARF_QEMU_MEM_MB=8192 XTASK_QEMU_ACCEL=kvm XTASK_QEMU_SNAPSHOT=1 \
  XTASK_QEMU_QMP=/tmp/virgl_qmp.sock NARF_VBLK_IMG=target/cachyos-ext4-narf.raw \
  XTASK_SYSTEMD_PID1_TIMEOUT_SECS=220 \
  cargo xtask systemd-pid1 --arch x86_64 --features container \
  --hw-profile full --display gtk --gpu-backend virgl
```
QMP screendump: connect to the sock, `qmp_capabilities`, `screendump {filename, device:"vgpu0"}`.
Read greeter binaries out of the image WITHOUT booting (rootfs = GPT partition 2 @ sector
16893952, offset 8649703424 bytes):
```
debugfs -R "cat /usr/bin/startplasma-login-wayland" "target/cachyos-ext4-narf.raw?offset=8649703424" > /tmp/splw.bin
strings -n 8 /tmp/splw.bin | grep -iE "systemd|session|locale"
```

### Method reminders reinforced this session
- One boot is not evidence (huge variance; "Display server started" appears on SOME headless rolls too).
- Diagnostic builds change the failure (a heavy census flood manufactured an EARLIER journal-pileup deadlock + panic). Trust the light build; make probes silent-unless-anomalous.
- A missing `readiness::notify` is a LATENCY bug, not a wedge — the 10 ms backstop always re-scans infinite parks. A minutes-long stall = data genuinely never produced OR blocked on a synchronous cross-service call, not a lost wake.
- Verify memory against `git log` before acting — the "designed, not implemented" cgroup.events note was stale (it landed `e971b210`), and the "virgl wedges" note was stale.

## Goal

Boot the installed CachyOS system from its virtual disk with the NARF kernel,
reach a usable Plasma Wayland desktop in a GTK QEMU window, verify keyboard and
mouse input, and verify accelerated VirtIO GPU/VirGL rendering.

The final acceptance result must be the real CachyOS installation, not the
small generated Fedora fixture. The Fedora image is now the fast systemd/udev
integration gate used while fixing kernel ABI behavior.

## Local VM data

- Installed CachyOS disk: `target/cachyos-ext4-narf.raw`
- Fedora integration disk: `target/narf-fedora-vblk.img`
- Installer ISO used successfully:
  `/home/daniel/Downloads/cachyos-desktop-linux-260809.iso`
- The older `260308` ISO was too old and did not install successfully.
- CachyOS user: `narf`
- CachyOS user password: `narf`
- Root login: `root`
- Root password: `narf`
- Preferred VM size: 8 GiB RAM and 2 vCPUs. Earlier smaller runs were
  repeatedly mistaken for guest OOMs; at least one later failure was actually
  an xtask/PTTY output error, and the current udev failure is a starved
  uevent path rather than an OOM.
- Final display: GTK with GL enabled.
- Final GPU: VirtIO DRM/VirGL, not the null driver and not only a software
  framebuffer.

The CachyOS disk was reinstalled and its partitioning was manually checked.
Do not reinstall again unless a fresh read-only inspection proves the current
disk is unusable. EFI, ext4 metadata checksums, UUID device aliases, and ext4
write support have all received fixes on this branch.

## Git state

- Working branch: `cachyos-efi`
- Do not put these commits on `main` and do not merge them automatically.
- Current HEAD when this document was written: `ee7b6a1f`
- Current `origin/main` when this document was written: `a2d5d7ad`
- The branch therefore needs a deliberate rebase onto the latest
  `origin/main` before final acceptance, after preserving and testing any local
  work.
- The worktree was clean when this file was created. Temporary udev datagram
  logging and the temporary disabled syscall trace filter had already been
  removed.

Recent branch commits, newest first:

- `1909130d Add marker-gated udev seat integration test`
- `c758c32f Preserve nonblocking activation sockets`
- `34dfa03f Provide writable var tmp for distro services`
- `1ec95139 Advance ext4 initialized inode boundary`
- `7ed5e9f4 Replay DRM coldplug to graphical login`
- `5dc396dc Satisfy GPU render path clippy checks`
- `ca7518ea Alias filesystem UUIDs as systemd devices`
- `2a202354 Skip clean shared pages during fsync`
- `0514ffa9 Fix container mqueue clippy warning`
- `2219a037 Quarantine corrupt ext4 allocation groups`
- `2d566a12 Support checksum-safe ext4 HTREE mutation`
- `cb41daf7 Enable checksum-safe ext4 metadata writes`

The exact hashes may change after a rebase; use commit subjects to identify the
work.

## What is already implemented

- Installed-distro root disk boot support through `NARF_VBLK_IMG`.
- EFI/ext4 boot-path fixes needed by the CachyOS installation.
- Writable ext4 checksum support, including checksum seed/HTREE-related work.
- Filesystem UUID aliases used by systemd device units.
- VirtIO DRM/card exposure and GPU render-path permission fixes.
- Input and Plasma/foot were reached in earlier runs, although input and the
  desktop were not yet consistently usable.
- Writable `/var/tmp` behavior needed by distro services.
- Preservation of `O_NONBLOCK` on inherited/socket-activated file
  descriptions, with an ABI regression test.
- A marker-gated Fedora systemd/udev seat integration test:
  `verification/data/musl-demo/fedora-udev-seat-gate.sh`.
- `cargo xtask systemd-pid1` supports explicit success and failure markers and
  no longer aborts merely because mirroring output to a tmux/PTTY encounters
  `EAGAIN`.

The marker gate requires both:

1. `/run/udev/data/c226:0` containing `G:master-of-seat`.
2. logind reporting `CanGraphical=true`.

It emits `NARF_UDEV_SEAT_PASS` or `NARF_UDEV_SEAT_FAIL` and explicitly
retriggers DRM once on failure to distinguish missed coldplug from a persistent
ABI failure.

## Current blocker (revised 2026-08-14, second session)

**`systemd-udevd` is healthy and idle — it receives no uevents.** It is parked
in `epoll_wait` with an infinite deadline and nothing ever becomes readable, so
it never forks a worker, so `/run/udev/data/c226:0` is never written and
`udevadm settle` times out. Chase kernel→udevd uevent delivery, not udevd.

Reproduced five times. The gate reaches real systemd PID 1 and
`graphical.target` and fails deterministically in roughly 43 seconds.

Evidence, from builds with
`--features container,unix-latency-trace,stall-watchdog`:

- The process roster contains exactly two `systemd-udevd` tasks per boot (the
  original plus one restart) and **no children of either** — zero workers for
  the whole run. `systemctl status`'s `Tasks: 1` is accurate here, not a
  cgroup-accounting artifact.
- udevd's `park_checks` advances normally (456 → 1429 → 2382 → 3352 across
  successive censuses) and its scheduler slot is polled tens of thousands of
  times. It is being scheduled; it has nothing to do.
- `journalctl -b -u systemd-udevd.service` prints `-- No entries --`, so
  udevd's own log is not available from inside the guest. Do not build a plan
  around reading it.
- The whole machine goes quiescent at around 1.47M syscalls: every task parked,
  one CPU idle-halted with **`awake=0`** across its entire ready queue. Nothing
  is waiting to run. This is an idle system waiting on an event that never
  arrives, not a scheduling failure.

### A correction worth keeping

An earlier reading of the first stall dump — "CPU 0 halted with 18 runnable
tasks, therefore a lost wakeup" — was **wrong**, and the way it was wrong is
reusable. In that dump CPU 0 was the REPORTING cpu, and the reporter is by
definition the one running, so its `awake=5` said nothing about a lost wake.
`ready_depth` also counts parked slots waiting to be polled, not runnable work.

The per-slot dump added to the watchdog (`STALL-WD   ready cpu=…`) is what
settled it: on the genuinely idle CPU every slot reads `awake=false`, and the
awake slots all sit on the reporting CPU with their `pops` climbing. Read
`awake` per slot; never infer a lost wakeup from `ready_depth` and the
summary `awake` count, and always check which cpu is `REPORTING`.

Note also that `STALL-WD: scheduler forward progress stopped` panics the
kernel at ~48 s. It fires on flat syscall/progress counters, so a legitimately
idle-but-deadlocked system trips it exactly like a scheduler bug would. The
panic is a symptom of the wedge, not evidence about its location, and it only
exists in `stall-watchdog` builds.

### ANSWERED: the uevent IS produced. The fault is downstream.

The doc previously asked whether the kernel never produces udevd's uevents
or produces them without ever reporting the socket readable. Measured on the
Fedora gate (commit "Report boot uevent coldplug health and consumers"):

```text
uevent: seqnum=11 ring=10/256 replay_start=2 coldplug_overrun=false
uevent:   #3 add@/devices/platform/narf-drm/card0 SUBSYSTEM=drm
uevent:   #4 add@/devices/platform/narf-drm/renderD128 SUBSYSTEM=drm
```

The DRM ADD exists, at seqnum 3, INSIDE the replay window (start = 2), and
the ring never overruns — 10 events total against a 256-entry ring. The ring
capacity comment ("256 entries covers typical boot") invites an overflow
theory; the measurement kills it. Neither is the readiness path at fault:
`poll_readiness` sets `POLL_IN` whenever `reader.has_pending()`, and the
existing `smoke_abi_netlink_uevent_recv` already covers emit → readable →
recv.

### FIXED: udev now publishes its database (mount-namespace resolver gap)

**Root cause.** `open`/`read` resolve through `current_resolve_absolute()`,
which consults the task's `MountNamespace`. Every directory-MUTATION syscall
— rename, renameat2, unlink, rmdir, symlink — called
`registry().resolve_parent_absolute()` directly, because no namespace-aware
equivalent existed. A task in a private mount namespace could CREATE a file
it could not then rename or unlink.

`systemd-udevd` runs `PrivateMounts=yes`, and `sd-device` publishes each
database entry by writing `/run/udev/data/.#<id><random>` and renaming it
onto `/run/udev/data/<id>`. The write succeeded; the rename returned ENOENT.
One cause, all three of udevd's error families:

```text
sd-device: Failed to rename temporary database file '/run/udev/data/.#+pci:...' to '...'
Failed to create device symlink '/dev/char/226:0': No such file or directory
Failed to open old watches directory '/run/udev/watch/': No such file or directory
```

Fixed in "Resolve directory mutations in the caller's mount namespace"
(RED→GREEN test that mounts a memfs into a private namespace only).

**Measured effect:** "Failed to rename temporary database file" drops from
every device to ZERO; devices reach `Device processed`;
`/run/udev/data/c226:0` is created carrying `G:master-of-seat` /
`Q:master-of-seat`; logind reports `CanGraphical=b true`. Both gate
conditions are now satisfiable.

### THE GATE HAS PASSED ONCE — and the discriminator is udevd aborting

```text
narf-udev-seat-gate[11]: NARF_UDEV_SEAT_PASS card0=master-of-seat CanGraphical=yes
[  OK  ] Finished narf-udev-seat-gate.service - Verify udev DRM seat integration on NARF.
```

That is a real guest-emitted PASS, on a build with
`--features container,unix-latency-trace,stall-watchdog`. Three subsequent
runs of the PLAIN `--features container` build failed. The difference is not
the features themselves — it is how many times udevd aborts:

| build                | `Started systemd-udevd.service` | result |
|----------------------|--------------------------------|--------|
| +latency-trace +stall-watchdog | 1 (no abort)          | **PASS** |
| plain container (×3) | 3 (two aborts each)            | FAIL   |

**The gate passes exactly when udevd does not abort.** The debug build is
slower — every diagnostic line goes to a synchronous serial console — and
that extra latency changes the interleaving enough to avoid the abort. So
the remaining blocker is a RACE, and the abort count is a clean,
one-number discriminator for it: check `grep -c "Started systemd-udevd"`
before reading anything else.

In the failing runs the udev database and `CanGraphical=b true` BOTH appear,
but only after the gate's loop has given up and run its explicit retrigger —
because the first udevd instance aborts mid-boot-replay and the restarted
one processes the retriggered event cleanly.

### The race: `assert(worker->event)` at udev-manager.c:1199

```text
Notify message sent: "PROCESSED=1"                 <- a worker finishes a device
Notify message sent: "INOTIFY_WATCH_REMOVE=1"      <- next device, same or other worker
Maximum number (18) of children reached.
Assertion 'worker->event' failed at src/udev/udev-manager.c:1199
```

`on_worker_notify` DETACHES a worker's event for any message that is neither
`INOTIFY_WATCH_ADD` nor `INOTIFY_WATCH_REMOVE` — `PROCESSED=1` is such a
message (udev-manager.c:1218). On Linux the ordering is safe because the
manager sets `worker->event` in `event_run()` BEFORE the worker can emit its
next `INOTIFY_WATCH_REMOVE=1`. Here the manager processes that message while
`worker->event` is still NULL.

**Ruled out by measurement, do not re-walk:**

- Credential misattribution — zero "unknown process" warnings after the
  per-receiver ancillary fix (which is landed and correct regardless).
- Netlink unicast misrouting — there are NO unicast netlink sends at all;
  the manager spawns fresh workers (initial device handed over in-process)
  rather than reusing idle ones, so that path never runs.
- `getpid()` after fork returning the parent's pid — now pinned by test
  (fork gives a new pid, CLONE_THREAD shares it). The `systemd-udevd[4]`
  log prefix is the service's journal-stream identity, not the writer's pid.

### Perturbation bisection so far (method: change ONE thing, count aborts)

The abort count is the signal — `grep -c "Started systemd-udevd"`; 1 means
no abort, 3 means two. Two perturbations run, both NEGATIVE, both cheap:

| perturbation | udevd starts | verdict |
|---|---|---|
| `NARF_QEMU_SMP=1` (×2 runs) | 3 | **Not a cross-CPU race.** It reproduces on a single CPU, so it is cooperative-scheduling ordering, not an SMP data race. |
| 5 ms delay on every `(udev-worker)` AF_UNIX notify send | 3 | **Not the notify-vs-bookkeeping window.** Widening the gap between the worker's sd_notify and the manager's `worker_new()`/`worker_attach_event()` changes nothing. |

The second one is worth understanding, because the structural race in
systemd LOOKS like the obvious culprit and is not:

```c
r = pidref_safe_fork(...);
if (r == 0) { udev_worker_main(&w, event->dev); }  /* child starts at once */
r = worker_new(&worker, manager, worker_monitor, &pidref);
worker_attach_event(worker, event);                /* ->event set only here */
```

`event_run()` has the same shape — `device_monitor_send()` to the worker
BEFORE `worker_attach_event()`. But the manager is single-threaded and
dispatches notify messages only from its event loop, which it re-enters
after that bookkeeping completes. So an early-arriving message is merely
QUEUED, not mis-dispatched, and delaying it makes no difference. That
matches the measurement.

**Netlink unicast is now CLOSED for good** — re-measured on a current build,
on a run that FAILED (3 udevd starts), so there is no timing confound:

```text
13 nl-send: comm=(udev-worker) proto=15 to_port=0 to_groups=2   <- broadcast to libudev
 6 nl-send: comm=systemd       proto=0  to_port=0 to_groups=0
 4 nl-send: comm=(systemd)     proto=9  to_port=0 to_groups=0
```

Zero sends with `to_port != 0`, and — more telling — **the manager never
sends on its monitor at all**: there is no `comm=systemd-udevd proto=15`
line of any kind. So `event_run()` never reaches `device_monitor_send()`,
which is consistent with the zero occurrences of "did not accept message,
killing the worker" in the debug log.

A worker therefore only ever receives the ONE device it was forked for, and
that device is attached by `worker_attach_event()` immediately after the
fork. Counts from the debug run (halved — the digest doubles serial lines):
**22 workers forked, 16 devices processed, 0 worker exits.**

That leaves exactly one way for `worker->event` to be NULL when an
`INOTIFY_WATCH_REMOVE=1` from that worker is dispatched: the manager already
processed a `PROCESSED=1` from the SAME worker, which detaches the event
(udev-manager.c:1218). In send order a worker emits
`INOTIFY_WATCH_REMOVE` → `INOTIFY_WATCH_ADD` → `PROCESSED=1`, so this
requires those datagrams to be dispatched OUT OF ORDER.

**REOPENED: credential misattribution.** The earlier closure was logically
invalid. It rested on zero "Received notify datagram of unknown process"
warnings — but that warning only fires when a datagram is attributed to a
pid that is NOT a registered worker. Attribution to a VALID-BUT-WRONG worker
produces no warning anywhere, and that is precisely the shape
`assert(worker->event)` detects. Absence of an error log only rules out the
logged branch. (Generalize that: it is the silent-probe trap again, one
level up.)

### THE CAUSAL MODEL (Fable session, 2026-08-15): two pid-translation bugs

Confirmed against Linux (`kernel/signal.c`: `do_rt_sigqueueinfo` →
`kill_proc_info` → `find_task_by_vpid` — the pid is the CALLER's namespace
view, same as kill(2)):

**Bug A — `rt_sigqueueinfo`/`rt_tgsigqueueinfo` skip pid-namespace
translation.** `sys_kill` translates via `resolve_inner_pid`; the sigqueue
handlers do `pid_to_task_raw(raw_pid)` on the caller's in-namespace number.
systemd runs under `unshare --pid`, and the udevd manager acks every
worker's `INOTIFY_WATCH_*` with `pidref_sigqueue(SIGUSR1)` — a fd-less
PidRef, so it is `sigqueue(2)` → `rt_sigqueueinfo`. Untranslated, the ack
lands on whatever process owns that small number in the OUTER pid space
(something always does), the call returns 0, nothing is logged, and the
worker waits forever in `notify_and_wait_signal`. Hence: workers never
complete devnode devices, never go idle, are never reused (also why there
are zero manager unicast sends — `event_run` finds no idle worker), and
fresh forks pile up to `Maximum number (18) of children reached`. The
per-worker starvation IS the no-reuse observation.

**Bug B — `self_inner_pid`'s miss-fallback fabricates identities.** On a
missed `outer_to_inner(sender_outer)` it retries with the OBSERVER'S TASK
ID as the key. Task ids and outer pids share small integers in real boots,
so an unmapped sender's SCM_CREDENTIALS pid can translate to whichever
process is registered under the manager's task-id number — a valid, wrong
worker. `hashmap_get(manager->workers, &sender)` then finds a worker that
never sent the message, and `on_worker_notify` detaches or asserts on ITS
event: the udev-manager.c:1199 abort, with no warning at any layer. Linux
renders an unmapped pid as 0 in the observer's namespace, never as someone
else.

Both bugs are silent at every individual layer — the calls all succeed —
which is why seven per-layer hypotheses each measured "closed" while the
chain stayed broken.

### Bugs A+B LANDED (de7bd91e) — gate unchanged, but they unlocked the kill

Three plain-build gate runs after the fixes: still FAIL, 2-3 udevd starts.
The fixes are real (RED→GREEN, Linux-verified) but the abort has a third
leg. What changed: with acks routed correctly, card0 SEQNUM=3 now completes
INSIDE instance 1 (pre-assert) — the pipeline is healthier and the abort is
the only remaining killer.

### Bug C FIXED (2092bb58): uevent ring gated on group-1 membership

Landed with two RED-first tests. See the commit for the mechanism; the
`Processing device` storm (SEQNUM=2 seven times off one fork) is gone by
construction — a groups=0 worker monitor no longer receives the ring.
Gate re-measurement in progress.

### GATE STATUS after Bug C fix (2092bb58): abort GONE, new failure mode

Three plain-build runs: `Started systemd-udevd` = **1** in all three (was 3),
zero asserts, zero restarts. Bug C killed the abort as designed. But the gate
still reports FAIL, for a DIFFERENT reason:

- `/run/udev/data/c226:0` is present from ~10 s, contains `G:master-of-seat`
  (matches the gate's anchored `^G:master-of-seat$` grep), and stays present.
- `CanGraphical` reads `b true` in the final diagnostic.
- Yet the loop's per-iteration `db_ready && graphical` check never fires, so
  the pass marker isn't emitted before the 45-tick loop ends.

So `db_ready` is satisfied throughout; the un-satisfied leg is `graphical` —
logind's `CanGraphical` is false DURING the loop and true only after. This is
logind consuming the udev seat tag lazily, a genuine timing question, NOT a
gate-script bug — do not "fix" it by adding more patience. Instrumented
logind-debug run in flight to time when CanGraphical flips and why. Candidate
mechanisms: logind needs a `change`/`add` uevent it isn't getting for card0
now that worker monitors are correctly group-filtered; or logind's device
enumeration runs once early and isn't re-triggered.

This is real progress: three sessions of "udevd aborts" is resolved. The
remaining gap is one component downstream (logind seat assignment), and both
required values demonstrably exist.

### FINAL BLOCKER (logind CanGraphical): chase(/sys/dev/char/226:0) → EINVAL

The abort is fixed; the gate now fails on ONE downstream step. logind
debug (drop-in via debugfs, same technique as udevd) says it directly:

```text
sd-device: Failed to get target of '/sys/dev/char/226:0': Invalid argument
sd-device: Failed to get target of '/sys/dev/char/226:1': Invalid argument
```

Chain: logind resolves each SEAT-MASTER device by devnum →
`sd_device_new_from_devnum("226:0")` → `device_set_syspath(verify=true)` →
`chase("/sys/dev/char/226:0")` returns EINVAL → the DRM master is never
attached to seat0 → `CanGraphical` stays false → gate's `graphical` leg
never satisfied, even though `db_ready` (master-of-seat) is satisfied the
whole loop. Both the udev DB and CanGraphical=true DO appear, but
CanGraphical only after the gate window (logind retries/settles late).

This is NOT a timing bug and NOT a gate-script bug — do not add patience.

Key disambiguation already done:
- Only `226:0`/`226:1` (CARD nodes) show the error. Render nodes
  (`226:128/129`) do NOT — but that is because logind only chases SEAT
  MASTERS (card nodes) by devnum, NOT because render symlinks work. Do not
  infer "render works, card broken".
- `char_dev_link` creates both card and render `/sys/dev/char/226:N`
  symlinks identically (drm_sysfs_bridge.rs:370), target
  `../../devices/platform/narf-drm/card0`. Structurally symmetric.
- The `drivers/gpu` e2e tests readlink `/sys/dev/char/226:128/...` via
  NARF's KERNEL resolver and pass — but `chase` uses the SYSCALL path
  (`openat(O_PATH|O_NOFOLLOW)` per component + `readlinkat`), which the
  kernel-side test does not exercise. That syscall path is the suspect.
- NARF's `O_NOFOLLOW|O_PATH` handling (core.inc.rs:1037) is gated on
  `mnt_len == 0` and drives `resolve_async_nofollow(fs.root(), rel)`. It
  looks correct on read, which is exactly why it needs a RED test, not more
  reading.

RESOLVED to environmental (commit "Pin the sd-device DRM char-symlink chase
syscall path", 2 GREEN conformance tests). The exact chase syscall sequence
— `openat(O_PATH|O_NOFOLLOW|O_CLOEXEC)` → `newfstatat(AT_EMPTY_PATH)` (S_IFLNK)
→ `readlink`/`readlinkat` (target) — is CORRECT in isolation AND under a
private mount namespace. So the handler is not the bug.

The real-boot EINVAL is a RACE. EINVAL (not ENOENT) means the `226:0` node
EXISTS but is momentarily not a well-formed symlink when logind chases it.
Leading hypothesis (agent, verified against systemd chase.c/sd-device.c, not
inferred): chase `statx`es the O_PATH fd — the node captured at open — while
`readlinkat` RE-RESOLVES `parent_path + "/226:0"` through the global
registry; if udev coldplug is concurrently rebuilding `/sys/dev/char` those
two resolutions can disagree for an instant. A single-threaded kernel test
cannot stage that, which is why the reproducer stays green.

NEXT (boot probe, not a unit test): instrument the readlink/openat of
`/sys/dev/char/226:0` for a `systemd-logind`-comm task — log the node type
seen and whether `SysKobjDir::get_symlink("226:0")` hit vs `get_child`
(a directory) — across the udev coldplug window. Also audit whether anything
REBUILDS or replaces the `dev/char` kobject subtree after first creation
(a `get_or_create_child` that races a concurrent replace), and whether
`char_dev_link` is re-invoked per card in a way that transiently drops the
node. This is a distinct, harder investigation from the udev-abort chain;
the abort itself is fully fixed.

### pid-namespace translation AUDIT (2026-08-15)

Full 34-finding table saved to `docs/pidns_translation_audit.md` (tracked).
Root structural cause: `pgid_from_user` is the RAW twin of the correct
`pgid_to_user` — the IN half of the pgid boundary skips the inner→outer hop
its OUT half performs. Top 5, all silent-until-a-real-consumer-breaks:

1. **`pgid_from_user` (#3)** drives `kill(-pgid)`, `setpgid`, `getpgid`,
   `TIOCSPGRP` — all job control. Fix one helper, four rows close.
2. **`getsid` (#7) — LANDED** (commit "getsid: return the session id in the
   visible-pid space"): the one finding wrong in non-container builds too.
   RED→GREEN, isolated to sys_getsid.rs.
3. **`ptrace` (#2)** translates NOTHING — the only finding that is a
   containment ESCAPE with write primitives (ATTACH+POKE a host pid).
3. **plain `kill`/`tkill` + SIGCHLD `si_pid == 0` (#8/#9)** — same consumer
   as the already-fixed pidfd path (udevd `on_sigusr1`, systemd PID 1
   `manager_dispatch_signal_fd`); the plain path never threaded a siginfo.
4. **`getsid()` returns a raw TaskId (#7)** — wrong in NON-container builds
   too; one-line fix (`pgid_to_user(read_sid(...))`).
5. **`fork()` after `unshare(CLONE_NEWPID)` (#13)** returns the child's
   NEW-ns pid to a parent in the OLD ns → `waitpid` ECHILD. UNSURE: an
   in-tree comment claims the coupling is deliberate; verify against
   `project_pidns_flow_model` first.

VERIFIED-CORRECT (re-runnable checklist) is in the doc, including the
provenance cases file-level greps miss: `tkill`/`tgkill` cover their tid via
`signal_tid_from_user`→`accept_pid_from`; the pidfd family is covered because
`pidfd_open` is the sole mint path and translates before `mint_for`.

Method note: the callchain graph (semcode + qualified-path grep, because the
index misses `crate::`-qualified calls) and the file-reading audit were run
in parallel and cross-checked — the graph caught one false positive the file
view would have flagged (`tkill`), the file view caught one gap the graph
missed (#26, the non-leader-thread raw-tid arm inside the shared helper).

### Bug C — FOUND: the uevent ring is delivered without group membership

The decisive instrument was the dispatch-sequence probe cachy.md
prescribed, run at SMP=1 for a clean serial stream (`udevm-rx:` lines in
userspace/src/socket.rs UnixDgram Recv, behind unix-latency-trace). The
manager's dequeues before the first assert:

```text
udevm-rx: outer=12 inner=12 payload=PROCESSED=1
udevm-rx: outer=12 inner=12 payload=PROCESSED=1
udevm-rx: outer=16 inner=16 payload=INOTIFY_WATCH_REMOVE=1
udevm-rx: outer=17 inner=17 payload=INOTIFY_WATCH_REMOVE=1
udevm-rx: outer=12 inner=12 payload=INOTIFY_WATCH_REMOVE=1   <- assert here
```

One worker sending [PROCESSED, PROCESSED, REMOVE] is impossible — unless it
processes multiple devices. And the per-SEQNUM counts prove it:

```text
1× "Worker [N] is forked for processing SEQNUM=2"  but  7× "Processing device (SEQNUM=2"
1× spawn for SEQNUM=3                              but  6× "Processing device (SEQNUM=3"
```

Workers re-receive devices on their MONITORS. Eliminated in order, one
measurement each: duplicate fork pids (all unique), worker_new EEXIST
(zero "Failed to create worker object"), manager unicast (zero
`monitor(manager): Passed` lines), user-broadcast leakage
(`broadcast_netlink_user` DOES check `netlink_memberships`), stale
namespace bindings (`bind_outer` callers are only inherit/unshare).

What remains is the ring: **`SocketFile::new` attaches the kernel-uevent
ring reader to EVERY proto-15 socket unconditionally.** udev workers create
their monitors `MONITOR_GROUP_NONE` (groups=0) — on Linux a netlink socket
receives kernel multicast ONLY when its bind-time `nl_groups` mask includes
group 1. On NARF every worker monitor is a full ring subscriber WITH the
boot-coldplug replay (created in the manager process, whose comm passes the
replay-eligibility check). Every worker therefore re-processes the whole
coldplug set; a worker re-processing a devnode device sends
`INOTIFY_WATCH_REMOVE=1` the manager never expected → hashmap finds the
real worker, its event long since detached → `assert(worker->event)`.

This also explains the timing sensitivity cleanly: slower builds serialize
worker lifetimes, so fewer monitors exist concurrently when the ring
replays, and the storm misses the assert window.

Fix (in flight, test-first): `netlink_uevent_subscribed` flag set at bind
when `groups & 1 != 0`; ring delivery/readiness/inq gated on it; user-inbox
unicast/broadcast paths untouched (their membership check already exists
and worker monitors legitimately receive unicasts at groups=0).

### New test suite: `userspace/src/abi_udev_protocol_tests.rs`

Four staged tests model the manager↔worker contract (fork in pid ns →
sd_notify with SCM_CREDENTIALS → `rt_sigqueueinfo` ack → signalfd
`ssi_pid == manager_pid`), one rule per test so a violated rule names
itself. Run with:

```bash
cargo xtask test --arch x86_64 --features container --subsystem syscall_abi/udev
```

**COVERAGE FINDING: the default `cargo xtask test` build has NO `container`
feature, so every `#[cfg(feature = "container")]` test — including the
long-standing pidns credential tests in abi_socket_tests — silently
registers ZERO tests in default CI runs.** "0 pass, 0 fail" from a
subsystem filter means the feature gate ate the module, not that the filter
missed. Follow-up worth doing: add a `--features container` test pass to
run_ci_locally.sh, or these tests guard nothing.

### Superseded by the causal model (kept for the method lesson)

**Datagram ordering is CORRECT — tested, and that closed a structural
candidate.** Commit "Pin AF_UNIX datagram ordering across sender sockets and
tasks": three `sd_notify`-shaped sends from three fresh sockets arrive in
order, queued datagrams outlive the sockets that sent them, and two sender
TASKS interleaved A,B,A,B come back A,B,A,B (a per-sender queue would give
A,A,B,B). Both verified red by switching the inbox to `push_front`.

### Where that leaves the abort

Every structural route to `assert(worker->event)` that this session could
generate is now measured closed:

| candidate | how it was closed |
|---|---|
| credential misattribution | zero "unknown process" warnings after the per-receiver ancillary fix |
| netlink unicast misrouting | zero unicast sends exist; the manager never sends on its monitor at all |
| worker gets an unassigned device | only route is unicast, which never happens |
| notify-vs-bookkeeping window | 5 ms delay on worker notify changed nothing |
| cross-CPU race | reproduces at SMP=1 |
| message reordering | tested, order is correct |
| `getpid()` after fork | tested, correct |

The abort is real and reproducible (2 per failing boot; 0 on the one passing
boot), so something IS wrong — but it is not any of the above, and the
remaining search space is no longer reachable by generating hypotheses from
the systemd source. **Change instrument: capture the manager's ACTUAL
dispatch sequence.** Log, kernel-side, every datagram the manager dequeues
from its notify socket with sender pid and payload prefix, and every fork it
performs, in one stream. The assert then names itself: the log will show
which worker's `PROCESSED=1` preceded which `INOTIFY_WATCH_*`, or show that
it did not — and if it did not, the fault is inside udevd's own bookkeeping
rather than in anything NARF delivers.

Note the earlier `uevent-rx`-style probes are the wrong shape for this: they
are per-socket, and this question is about the manager's per-dispatch
ORDER. Budget the new probe at 4000 lines (a 64-line budget was spent by
PID 1 before udevd started and produced two wrong conclusions).

**Method note:** both perturbations cost one boot each and eliminated a
hypothesis outright. That is a far better rate than this session's
read-the-source hypotheses, which went 0-for-7. Prefer it.

### How to get udevd's log (this is the tool that cracked it)

journald cannot capture udevd this early, and `systemd.setenv=` /
`systemd.default_standard_error=` on the kernel command line both failed to
route it. What works is a drop-in installed directly into the ext2 fixture
with `debugfs`, no image regeneration and no root:

```bash
printf '[Service]\nEnvironment=SYSTEMD_LOG_LEVEL=debug\nEnvironment=SYSTEMD_LOG_TARGET=console\nStandardOutput=journal+console\nStandardError=journal+console\n' > /tmp/99-narf-debug.conf
debugfs -w -R "mkdir /etc/systemd/system/systemd-udevd.service.d" target/narf-fedora-vblk.img
debugfs -w -R "write /tmp/99-narf-debug.conf /etc/systemd/system/systemd-udevd.service.d/99-narf-debug.conf" target/narf-fedora-vblk.img
# ... run the gate with a 150 s timeout ...
debugfs -w -R "rm /etc/systemd/system/systemd-udevd.service.d/99-narf-debug.conf" target/narf-fedora-vblk.img
debugfs -w -R "rmdir /etc/systemd/system/systemd-udevd.service.d" target/narf-fedora-vblk.img
e2fsck -fn target/narf-fedora-vblk.img   # confirm the fixture is still clean
```

That yields ~1000 lines of udevd debug on the serial console and answers in
one run what a week of black-box inference did not. REMOVE THE DROP-IN
AFTERWARDS — it is a shared fixture.

### Corrections this produced

The debug log also retired two conclusions reached from outside:

- **udevd DOES fork workers** ("Worker [12] is forked for processing
  SEQNUM=5"). The earlier "zero clone calls" came from a syscall trace
  filtered to the manager's tid; workers are separate tasks.
- The `assert(worker->event)` abort at `udev-manager.c:1199` is real and
  does fire, so cachy.md's original note was right — it is a CONSEQUENCE of
  workers failing mid-process, not the cause.

### Two probe mistakes to not repeat

Both cost a wrong conclusion, and both are the same mistake:

- The uevent receive trace had a 64-line budget. PID 1's own monitor spent
  ~60 of them before udevd started, so udevd appeared to read two events and
  stop. It does not — it reads all of them.
- The unbounded-epoll-park probe had a 48-line budget, spent by PID 1 and
  systemd-tmpfiles before udevd started, so udevd appeared never to park.

A capped probe going quiet is indistinguishable from the thing it watches
going quiet. Both budgets are now 4000. Before drawing any conclusion from a
probe's silence, check whether the probe was still running.

### Ruled out this session

- Ring overflow / lagging-reader eviction (measured: no overrun).
- Uevent production (measured: DRM ADD present in the replay window).
- Netlink readiness reporting (covered by existing tests).
- `waitid` child-exit wake — see the CachyOS section.
- Scheduler lost wakeup — see the correction note above.
- Duplicate boot-replay per monitor — attempted, REVERTED: granting the
  window once per consumer starved the socket-activation fd (udevd started
  at seqnum 11 instead of 2 and lost the DRM ADD at 3). Pinned by test.
- statx identity across two opens of one directory (measured stable).
- udevd being merely slow rather than stuck (300 s untraced run).
- udevd failing to spawn workers (it never calls clone at all).

### Reproduce with diagnostics

```bash
env CARGO_BUILD_JOBS=8 CARGO_INCREMENTAL=0 NARF_QEMU_MEM_MB=4096 \
  NARF_QEMU_SMP=2 XTASK_QEMU_ACCEL=kvm XTASK_QEMU_SNAPSHOT=1 \
  NARF_VBLK_IMG=target/narf-fedora-vblk.img \
  XTASK_SYSTEMD_PID1_TIMEOUT_SECS=95 \
  XTASK_SYSTEMD_PID1_SUCCESS_MARKER=NARF_UDEV_SEAT_PASS \
  XTASK_SYSTEMD_PID1_FAILURE_MARKER=NARF_UDEV_SEAT_FAIL \
  cargo xtask systemd-pid1 --arch x86_64 \
    --features container,unix-latency-trace,stall-watchdog \
    --hw-profile full --display none --gpu-backend virtio-2d
```

`stall-watchdog` is required for the census: `dbg_park_census` /
`dbg_proc_roster` live inside `frame/src/x86_64/trap.rs`'s `stall_wd` module,
which is itself `#[cfg(feature = "stall-watchdog")]`. Building with
`unix-latency-trace` alone produces UNIXENQ lines and no census at all — that
combination was tried and wasted a run.

`XTASK_QEMU_APPEND` appends to the guest kernel command line (for example
`trace_comm=systemd-udevd` with `--features syscall-trace`). A full syscall
trace under SMP=2 interleaves badly across CPUs and is hard to read; the park
census is the better instrument. Tracing also slows the boot enough that the
gate script does not finish inside a 55 s timeout — raise the timeout when
tracing.

## CachyOS acceptance boot — actually attempted (2026-08-14)

Run with `XTASK_QEMU_SNAPSHOT=1` added to the documented acceptance command,
so guest writes are discarded and the installed disk cannot be damaged by a
mid-boot wedge. Drop it only for a run that genuinely needs persistence.

**CachyOS is wildly non-deterministic. Two boots of the SAME image and
near-identical kernels:**

- Boot A (`--features container`, 420 s): NARF boots clean (splash painted on
  virtio-gpu, ext2 mounted, 13 drivers), systemd 261.2 prints its banner and
  `Welcome to CachyOS!` — then **nothing for 7 minutes**. Zero units. xtask's
  digest found 2 systemd-relevant lines in the whole capture.
- Boot B (`+unix-latency-trace,stall-watchdog`, 150 s): **reached
  `multi-user.target` with 54 units started.** `graphical.target` was queued as
  the default job but never reached, and no display-manager/SDDM line appears
  at all. NetworkManager and Avahi fail-loop continuously.

Never conclude anything about CachyOS from one boot. The doc's earlier
framing — that CachyOS is blocked on the same thing the Fedora gate is —
does not survive contact: boot B gets much further than the Fedora fixture in
some respects and much less far in others.

### REFUTED: `waitid` is not the CachyOS defect

The census caught parents parked in `waitid(pid, WEXITED)` beside children
already in `TASK_ZOMBIE`, in both boots, and that looked like a missing
child-exit wake. Tested first rather than fixed — and the tests came back
GREEN (commit "Pin waitid reap and child-exit wake contracts"). Both
orderings work in the root namespace:

- child exits, THEN the parent calls blocking `waitid` → reaps off
  `PENDING_EXITS` with a correctly filled `siginfo_t`, never parks;
- the parent's wait-child waker is registered, THEN the child exits →
  `on_child_exit` fires the waker and the post-wake re-check reports the
  child with the right wstatus.

`PARENT_OF` keying was the other suspect and it checks out: it is keyed by
the child's OUTER `ProcessId` (`alloc_pid().raw()` at fork) and read with
the same outer pid from `notify_task_exited`, storing the parent's TaskId —
which is the key `register_wait_child_waker` / `wake_wait_child` /
`PENDING_EXITS` all use. Consistent on both sides, so the pid-namespace
angle does not apply here either.

**Two ways the original reading was over-confident, both worth avoiding:**

1. A parent parked in `waitid` next to a zombie child is the NORMAL
   transient between exit and reap. It only means something if it
   persists, and boot B had just two samples of it — while that same boot
   went on to reach `multi-user.target`, so nothing was permanently wedged
   there at all.
2. A frozen `park_checks` counter is NOT evidence for this park.
   `sys_waitid`'s own comment says so: `own_stack_wait_child` "does not
   tick `dbg_park_checks`". A waitid waiter therefore looks identical
   whether it is stranded or healthy. Use the census for poll/epoll parks;
   for wait parks, write a test.

The tests are kept: that contract had no coverage, and it is now ruled out
by construction rather than by argument.

### Second signal: journal stdout backlog never accepted

Persistent across both boots, for the entire run:

```text
UNIXPEND ms=76494 name=/run/systemd/journal/stdout n=13 ready=0x1 \
         owner_tid=14 owner_fd=47
```

13 connections queued on `/run/systemd/journal/stdout`, the listener reported
READABLE, and nobody accepting. Every service's stdout connects here, so this
backpressures the whole boot. `owner_tid=14` is PID 1 only because
`listen_owner_tid` records who called `listen()`; journald inherits the fd and
is the one that should accept. Check whether this is a consequence of the
`waitid` strand (journald itself was one of the frozen tasks in boot A) before
treating it as independent.

## Superseded hypotheses

Neither of the following reproduced this session. Do not spend time on them
until the scheduler stall is fixed and the gate is re-measured.

- **`systemd-udevd` SIGABRT at `udev-manager.c:1199 assert(worker->event)`.**
  No `[process-exit]` record for udevd appeared in a `syscall-trace` run, and
  the udevd instances observed were parked, not crashing. udevd *is* restarted
  once or twice per boot, but the cause was not captured.
- **The connectionless AF_UNIX datagram ancillary race** described under
  "Datagram evidence" below. Still a real latent defect worth fixing on its
  own merits — the socket-global `last_recv_cred` / `last_recv_fds` slots are
  genuinely not per-record — but it cannot be the cause of a udevd that never
  runs its event loop. Re-measure after the stall is fixed before writing the
  two-receiver test.

## Fixed this session

`pidfd_send_signal(2)` discarded the caller's `siginfo_t` (commit
"Carry pidfd_send_signal siginfo to the target"). Linux's
`do_pidfd_send_signal` copies a non-NULL `info` and delivers it verbatim;
NARF dropped it, so the target's `signalfd` read saw `ssi_code == 0` and
`ssi_pid == 0`. systemd's `pidref_sigqueue()` is exactly this call, and a udev
worker's `on_sigusr1` ignores any SIGUSR1 whose `ssi_pid` is not its manager —
so a worker that got as far as `udev_watch_end()` would have blocked forever
waiting for an acknowledgement it had already been sent.

This is a real ABI gap with a RED→GREEN regression test, but it did NOT move
the gate: workers never get far enough to send `INOTIFY_WATCH_REMOVE=1`. Keep
it; it will matter once the scheduler stall is fixed.

Left open deliberately, pinned by a `// LINUX-GAP` test: a payload-less send
(`info == NULL`, and the whole `kill`/`tkill`/`tgkill` family) still reports
`ssi_code 0` / `ssi_pid 0` where Linux synthesizes `SI_USER` plus the sender's
pid and uid. Closing that has to be done for the family at once.

## Historical: the udevd assertion (not reproduced)

The fatal process record is:

```text
[process-exit] kind=signal ... comm=systemd-udevd signal=6 core_dumped=true ip=4090005c432c
```

Symbolizing the Fedora 43 systemd 258.9 binary identified:

```text
../src/udev/udev-manager.c:1199
on_worker_notify
assert(worker->event)
```

The exact upstream source used for confirmation was downloaded locally to:

- `/tmp/systemd-v258.9-udev-manager.c`
- `/tmp/systemd-v258.9-udev-worker.c`
- `/tmp/systemd-v258.9-udev-watch.c`
- `/tmp/systemd-v258.9-notify-recv.c`
- `/tmp/systemd-v258.9-socket-util.c`
- `/tmp/systemd-v258.9-sd-daemon.c`

The assertion is in the `INOTIFY_WATCH_REMOVE=1` branch. A udev worker sends
that notification before processing a device and waits for the manager's
SIGUSR1 acknowledgement. The manager found a Worker object by the received
SCM credentials, but that Worker had no assigned event, which should be
impossible with correct message identity/lifetime behavior.

## Datagram evidence

A temporary trace was used once and then removed from the worktree. It showed
the manager receiving worker notifications such as:

```text
INOTIFY_WATCH_REMOVE=1
ERRNO=2
ERRNO_NAME=ENOENT
```

The send side showed distinct scheduler tasks and process IDs, for example:

```text
task=197 pid=12
task=198 pid=14
task=199 pid=15
task=200 pid=16
```

All sent to the same abstract AF_UNIX datagram notification socket. The manager
receiver was a different task (for example task 91, process 4). This is the
multi-worker/shared-receiver shape missing from the existing tests.

The current connectionless AF_UNIX datagram implementation stores
`last_recv_cred` and `last_recv_fds` in socket-global slots after dequeue, then
the recvmsg syscall reads those slots later. That is not atomic per received
record: another task sharing/inheriting the same receiver can overwrite the
slots between dequeue and ancillary extraction. Existing tests cover one
sender and PID-namespace translation, but not two receivers interleaving on a
shared socket.

This is the leading root-cause candidate. It still needs to be proved by a
failing regression test and by making the Fedora marker gate pass; do not call
it fixed before both happen.

## Changed debugging methodology

Do not use the full CachyOS GUI boot for each kernel ABI hypothesis. Use this
order:

1. Add a deterministic in-kernel ABI regression test.
2. Run only `syscall_abi/socket` while iterating.
3. Run fmt and clippy.
4. Run the Fedora marker-gated systemd/udev test.
5. Commit a self-contained tested fix.
6. Only after the gate passes, perform the CachyOS GTK/VirGL acceptance boot.

Diagnostics belong in tests where possible. Do not leave hot-path serial
logging, per-syscall traces, the temporary `UDEVDGRAM` prints, or fatal-path
stack dumping in the final patch.

## Next implementation

**Do this first: kernel→udevd uevent delivery, on the FEDORA gate.** Iterate
on Fedora, not CachyOS: the Fedora gate fails the same way five runs out of
five, while CachyOS ranges from "dead at the systemd banner" to
"multi-user.target with 54 units" on the same image. A signal you cannot
reproduce is not a signal you can bisect.

That measurement is DONE — see "ANSWERED: the uevent IS produced". Pick up
from "The live lead: udevd churns monitor sockets and reads almost nothing".

Concretely, next:

1. **Chase the ORDERING between the manager's two channels** — see "The
   assertion's actual shape". The credential angle is measured closed (zero
   "unknown process" warnings after the per-receiver ancillary fix), and the
   two-receiver datagram test is written and passing.
2. Watch "Maximum number (18) of children reached": workers accumulate rather
   than exiting, which is either a cause or a second bug.
3. Do not re-derive the once-per-consumer replay idea; it was tried,
   measured harmful, and reverted.

Only after the gate passes should the AF_UNIX datagram work below be
revisited.

### Deferred: two-receiver AF_UNIX datagram test

Add a deterministic two-receiver AF_UNIX datagram test that does the following:

1. Bind one abstract `SOCK_DGRAM` receiver with `SO_PASSCRED`.
2. Create at least two worker task/process mappings.
3. Send distinguishable messages from both workers.
4. Interleave dequeue/ancillary extraction from two tasks sharing the same
   receiver.
5. Assert FIFO, exactly-once delivery, and the correct per-message PID for
   every receive.

The current implementation should fail because its socket-global ancillary
slots are overwritten. Fix it by making delivered datagram ancillary state
record- or receiver-task-specific, then make the test pass. Also cover
`MSG_PEEK` for connectionless AF_UNIX datagrams: the current receive branch
ignores flags and always pops the queue, which is a separate Linux semantic
gap and may affect size-probe consumers.

Relevant code:

- `userspace/src/socket.rs`
  - `SocketFile::{last_recv_cred,last_recv_fds}`
  - `dispatch_unix_dgram_with_fds`
  - `recvmsg_cred`
  - `unix_take_recv_fds`
- `userspace/src/handlers/sys_socket_recvmsg.rs`
- `userspace/src/handlers/sys_socket_recv.rs`
- `userspace/src/abi_socket_tests.rs`
- Existing notify tests around
  `smoke_abi_socket_notify_path_dgram_epoll_scm` and
  `smoke_abi_socket_notify_sendmsg_pid_namespace_credentials`.

Before changing userspace socket behavior, read
`userspace/specification/spec.md`. If the visible ABI contract changes, update
section 3 in the same commit.

## Fast Fedora gate command

Run KVM outside the sandbox (a direct sandbox run cannot access `/dev/kvm`):

```bash
env \
  CARGO_BUILD_JOBS=1 \
  CARGO_INCREMENTAL=0 \
  NARF_QEMU_MEM_MB=4096 \
  NARF_QEMU_SMP=2 \
  XTASK_QEMU_ACCEL=kvm \
  XTASK_QEMU_SNAPSHOT=1 \
  NARF_VBLK_IMG=target/narf-fedora-vblk.img \
  XTASK_SYSTEMD_PID1_TIMEOUT_SECS=55 \
  XTASK_SYSTEMD_PID1_SUCCESS_MARKER=NARF_UDEV_SEAT_PASS \
  XTASK_SYSTEMD_PID1_FAILURE_MARKER=NARF_UDEV_SEAT_FAIL \
  cargo xtask systemd-pid1 \
    --arch x86_64 \
    --features container \
    --hw-profile full \
    --display none \
    --gpu-backend virtio-2d
```

Current result: `NARF_UDEV_SEAT_FAIL` after about 43 seconds (reproduced four
times on 2026-08-14, both with and without the pidfd_send_signal fix).
Required result: `NARF_UDEV_SEAT_PASS`, a DRM udev database entry with
`master-of-seat`, and `CanGraphical=true`.

Read the marker out of the guest's own output, not out of xtask's error text:
xtask echoes the configured marker name back in
`Error: ... observed failure marker "..."` / `timed out without success marker
"..."`, so a bare `grep NARF_UDEV_SEAT_PASS` matches on a run that never
passed. Grep for the emitted line (`NARF_UDEV_SEAT_PASS card0=`) instead.
xtask also replays the serial log as an indented digest, so every guest line
appears twice — drop lines starting with whitespace before counting anything.

## Focused verification

```bash
cargo xtask test --arch x86_64 --subsystem syscall_abi/socket
cargo fmt --check
cargo clippy -p narf-userspace --all-targets --features container -- -D warnings
```

Use the actual workspace-supported clippy invocation if the package/feature
combination differs after rebasing. Commit only after the focused test, fmt,
and clippy pass. Include the required `Co-Authored-By` trailer.

## Final CachyOS acceptance

After the Fedora gate passes and the branch is rebased/tested, remove any
temporary diagnostic unit left inside the CachyOS image and boot with:

```bash
env \
  CARGO_BUILD_JOBS=1 \
  CARGO_INCREMENTAL=0 \
  NARF_QEMU_MEM_MB=8192 \
  NARF_QEMU_SMP=2 \
  XTASK_QEMU_ACCEL=kvm \
  NARF_VBLK_IMG=target/cachyos-ext4-narf.raw \
  cargo xtask systemd-pid1 \
    --arch x86_64 \
    --features container \
    --hw-profile full \
    --display gtk,gl=on \
    --gpu-backend virgl
```

Do not mark the goal complete until all of these are observed:

- CachyOS reaches the Plasma desktop, not merely `graphical.target`.
- A foot terminal opens and accepts keyboard input.
- Mouse pointer movement and window dragging work.
- `/dev/dri/card0` and the render node are present with correct udev/logind
  seat metadata.
- Plasma/KWin uses the VirtIO DRM device rather than a null driver or software
  framebuffer.
- VirGL/accelerated rendering is positively verified from the guest, not
  inferred only from QEMU command-line flags.


---

## 2026-08-16 DECISIVE: greeter stall is NOT a NARF ppoll/eventfd wake bug

Added an `rdy=` (poll_readiness) field to the PARKFDS park census
(userspace/src/task.rs) and read the greeter process (pid=9) at **SMP=1**:

- **main** `startplasma-log` (tid=216): `ppoll([fd4])`, fd4 = `chr:rdy=0x4` —
  POLL_OUT ONLY (POLL_IN=0x1, POLL_OUT=0x4 per filesystem/src/lib.rs:1096).
  fd4 is an **empty eventfd**. The task is CORRECTLY parked; the wakeup byte
  was never written.
- **QDBus worker** `QDBusConnection` (tid=254, SAME pid=9):
  `ppoll([fd7 chr:rdy=0x4 empty, fd8 sock:rdy=0x4 idle])` — its own wakeup
  eventfd is empty AND the D-Bus socket has no pending reply, so NO D-Bus call
  is outstanding.

Reading: main poked the worker (write fd7) expecting a result posted back
(write fd4). The worker woke, found no work, re-parked. fd4 was never written.
Reproduces at SMP=1 ⇒ NOT a memory-ordering race. fd4 genuinely empty ⇒ the
10 ms backstop can't help (nothing to re-scan).

**Ruled out (all verified correct this session):**
- eventfd `write()` bumps the counter (io_mux.rs:109-119) BEFORE
  `readiness::notify(0)` (line 136) — no notify-before-bump lost-wake.
- `poll_readiness` returns POLL_IN iff counter>0 (io_mux.rs:173).
- ppoll returns immediately on a readable eventfd and 0 on an empty one — new
  tests `smoke_ppoll_eventfd_ready_returns_pollin` /
  `smoke_ppoll_eventfd_empty_returns_zero` (userspace/src/tests/epoll_poll.rs).

The whole NARF ppoll/eventfd/readiness machinery is SOUND. Residual = Qt's own
cross-thread event-post (QTimer::singleShot(0) job-start, or a
QDBusPendingCall watcher-finished post) not reaching main — works on good
rolls, so a race in Qt logic OR a NARF scheduler-fairness starvation of the
producer at the critical instant. STOP re-chasing this as a ppoll wake bug.

---

## 2026-08-16 Rebased onto origin/main; fixed a boot regression it introduced

Rebased `cachyos-efi` onto origin/main (PR #161, commit 289ba96a "memory:
scale mmap and complete VM range semantics", ~1726-line rewrite of
address_space.rs). The rebase REGRESSED the systemd boot: systemd PID 1 took
a fatal #PF (`W=1 P=1`) writing to the **vDSO** code page (0x7fff00001000) the
instant it started — no plasmalogin/greeter.

Root cause: the rewrite tightened `cow_split_on_write` to recover a present-RO
write only when the region carries BOTH WRITE and COW (to reject
mprotect(PROT_READ)), and updated `clone_for_fork` accordingly — but the vDSO
mapping in `userspace/src/vdso.rs::map_into` (a different crate) still declared
only `READ | EXEC`, relying on the OLD refcount-only cow_split. glibc's ld.so
writes the vDSO dynamic section in place → cow_split declined → fatal.

Fix: declare the vDSO region `READ | WRITE | EXEC | COW` (extracted as
`vdso::VDSO_CODE_PERMS`). W^X is not violated — it's enforced only at the
mmap/mprotect syscall entries, not on the vDSO's direct `map_region` path.

Verified: systemd survives, boot reaches udevd/logind/dbus-broker/plasmalogin/
startplasma/greeter again — back to the SAME Qt greeter stall (the fd4-empty
producer-side race), now on the new base.

Diagnostic added: `fault-vma=<a>-<b> r= w= x= shared=` on the fatal-fault dump
(commit 88455161). Tests added: memory `smoke_memory_vdso_shaped_cow_region_
splits_on_write` + userspace/process `smoke_process_vdso_region_perms_are_cow_
writable`. This class is invisible to GHA CI (no desktop/systemd boot).

### Greeter frontier (in progress on the rebased tree)

With the boot regression fixed, re-running the targeted D-Bus/Qt syscall trace
of the greeter's two pid=9 threads on the new base:

  trace_comm=startplasma-log,QDBusConnection  (--features container,syscall-trace, SMP=1)

Goal: distinguish the two remaining sub-cases of the fd4-empty producer stall —
  (A) main never posts the job-start (singleShot(0)) → worker has nothing to do
      → no D-Bus call → no post back to fd4; vs
  (B) main pokes the worker (write fd7), worker wakes but finds no work (lost /
      mis-targeted enqueue), so it never writes fd4.
Discriminators: does main write(fd7) after settling? does the worker read(fd7)
+ sendmsg(fd8) a D-Bus call + ever write(fd4)? Findings appended below when the
trace lands.

**FINDINGS (rebased-tree syscall trace, decisive — corrects the earlier
"producer-side race" conclusion):** traced the greeter's two pid=9 threads
(main t=230 `startplasma-log`, worker t=268 `QDBusConnection` bus :1.5).
The main↔worker handshake is CLEAN and COMPLETE, not a lost wake:
  main: write fd7 (poke worker) → futex WAIT @stack → [woken] → write fd4 +
        read fd4 (self-wake+drain its dispatcher) → write fd7 → ppoll(fd4,∞).
  worker: read fd7 → sendmsg fd8 (D-Bus) → recvmsg reply → recvmsg EAGAIN →
        futex WAKE @stack (wakes main) → read/write fd7 → ppoll(fd7,fd8,∞).
Both then park with drained eventfds + idle socket = a genuinely QUIESCENT
greeter, all work done, waiting for a NEXT event that never comes.

The greeter's ONLY substantive D-Bus call is a BLOCKING `locale1 GetAll` that
returns **ERROR NameHasNoOwner "Could not activate remote peer
'org.freedesktop.locale1': startup job failed"** — systemd's D-Bus activation
of systemd-localed FAILED. The greeter handles the (error) result, then its
main event loop parks forever (ppoll 1 fd, timeout=NULL, no timer pending, no
signal subscription). It never proceeds to KUpdateLaunchEnvironmentJob /
StartUnit. Hypothesis: the greeter's locale path only continues on a VALID
reply; the localed activation failure sends it down a dead-end.

NEXT LEAD (concrete, tractable): why does the systemd-localed start job fail on
NARF? Many services fail on NARF (network/avahi/utmp/remount — expected), but
localed is simple and Linux starts it. If localed starts → locale1 returns a
valid reply → greeter likely proceeds past the current wall. Also seen:
`systemd-logind: Failed to start session scope session-c1.scope: Connection
reset by peer`.

## 2026-08-16 BREAKTHROUGH: localed sandbox is the greeter blocker; next = user-runtime-dir@957

**Masking localed did NOT unblock the greeter** (still NameHasNoOwner "unit is
masked" → same dead-end): the greeter's blocking locale1 GetAll needs a VALID
reply, not a clean error.

**Bisection drop-in cracked it.** A drop-in at
`/etc/systemd/system/systemd-localed.service.d/override.conf` clearing localed's
sandbox (PrivateNetwork/PrivateDevices/PrivateTmp/ProtectSystem/ProtectHome/
ProtectProc/ProtectControlGroups/ProtectKernel*/ProtectHostname/
RestrictNamespaces/RestrictAddressFamilies=/SystemCallFilter=/IPAddressDeny=/
CapabilityBoundingSet=/NoNewPrivileges=no) → **localed STARTS**, locale1 GetAll
returns a valid a{sv} reply, and the greeter **ADVANCES PAST locale1** into the
user-session phase. So localed's start-job failure is in systemd's per-exec
SANDBOX SETUP (pre-exec, under a `(sd-*)` comm that trace_comm never matched —
that's why ~14 comm-scoped trace boots showed "no signal"; I was tracing PID 1).
BPF (ignored) + seccomp (skipped) are NOT the fatal piece.

**NEW BLOCKER (next):** `user-runtime-dir@957.service` hangs at `start running`
(→ `user@957.service` waits → the plasma session / kwin never start). Its unit
is a trivial `Type=oneshot ExecStart=/usr/lib/systemd/systemd-user-runtime-dir
start %i` with NO sandbox — so this is a DIFFERENT hang (the
systemd-user-runtime-dir binary blocking while creating /run/user/957, likely a
mount/syscall). Trace it with `trace_comm=systemd-user-ru`.

**Proper fix pending:** bisect the localed drop-in to pin the exact NARF-
incompatible sandbox directive (candidates: PrivateNetwork netns / ProtectSystem
mount-ns remount / PrivateDevices mknod / ProtectProc) and fix NARF to support-
or-ignore it — MANY services carry these directives, so a NARF-side fix is
needed, not per-service drop-ins. Diagnostics added: `trace_errors_only` +
sandbox-syscall + exit_group logging (commits 5a60a4b7, 951c1c4e).

### user-runtime-dir@957 blocker refined (2026-08-16)

Traced `systemd-user-runtime-dir` (comm `systemd-user-ru`, full trace): the
`start 957` invocation DOES its work — `openat /run/user/957` → `mount tmpfs ->
/proc/self/fd/3` (=0) → `exit_group(0)`. Yet the journal still shows
`user-runtime-dir@957.service  start running`. So the ExecStart binary succeeds
and exits 0, but **systemd never marks the oneshot done** → `user@957.service`
waits → plasma session / kwin never start.

=> Next lead is a systemd oneshot-completion / child-reaping issue for the
user-957.slice: PID 1 isn't registering the ExecStart's exit(0). Candidates:
SIGCHLD/waitid not reaping the child spawned via CLONE_INTO_CGROUP into the
user slice, OR systemd waiting on cgroup.events "populated=0" for that
sub-cgroup and NARF not reporting the empty transition (cf.
project_cgroup_events_inotify, fixed only for the leader cgroup). NOT a hang in
the helper itself.

Reproduce: boot with the localed sandbox drop-in in place;
`user-runtime-dir@957.service` stays `start running`. Trace PID 1's
waitid/SIGCHLD around the user-957.slice, or check cgroup.events on
/sys/fs/cgroup/user.slice/user-957.slice/... after the ExecStart exits.

### user-runtime-dir@957 blocker — narrowed to control-process reaping (Type=oneshot)

Code analysis (no fix yet):
- cgroup-empty path is CORRECT: `place()`/`attach_by_path` fire notify_events
  0->1, `task_exited(pid)` fires 1->0, `notify_events` (cgroupfs/mod.rs:376)
  walks UP and calls `notify_modify(<cgroup>/cgroup.events)` — this was the
  e971b210 fix for Type=FORKING units. CLONE_INTO_CGROUP placement keys on
  `child_visible_pid` (ProcessId), and the exit-observer keys task_exited on
  the same ProcessId, so keys should match.
- BUT user-runtime-dir@.service is **Type=oneshot** — its completion is driven
  by systemd REAPING the control (ExecStart) process, NOT cgroup-empty. The
  ExecStart process mounts /run/user/957 and `exit_group(0)`s cleanly, yet the
  job stays `start running` → systemd isn't registering the control-process
  exit. The clone3 that spawned it had CLONE_PIDFD (flags 0x300005100), so
  systemd is likely waiting on the child's PIDFD (poll) — same family as
  [[project_kwin_wayland_accept_gap]] (bbeaaf5e, Qt forkfd waitid(P_PIDFD)).

NEXT (empirical): trace PID 1 (systemd) at the user-runtime-dir exit — does it
poll a pidfd / waitid the child, and does that wake when the child exit_group's?
i.e. does the child's pidfd become readable + does waitid(P_PIDFD/the child)
return on exit for a CLONE_PIDFD child spawned into a sub-cgroup. Reproduce with
the localed sandbox drop-in in place; user-runtime-dir@957 stays `start running`.

### pidfd CONFIRMED not the blocker; lead = cgroup-empty for the oneshot

Added PIDFD-MINT/EXIT diagnostics (commit 54e6e2f9). Result for the
user-runtime-dir@957 ExecStart child (the one that mounts the /run/user/957
tmpfs, t=220): minted under ns-visible pid 16, exit fired with pid 16,
`pidfd_found=true` → its `exited` flag is set → PidFdFile::poll_readiness
returns POLL_IN → systemd reaps it. So the CONTROL-PROCESS REAPING IS CORRECT.
Yet user-runtime-dir@957.service stays `start running` after 300s (user@957
`start waiting` purely because it depends on it).

=> Since reaping works, the oneshot-completion hang is the CGROUP-EMPTY wait:
systemd tracks the service cgroup and finalizes the oneshot when it settles
empty. The general cgroup path is correct (place->notify_events 0->1,
task_exited->notify_events 1->0 walking up + notify_modify), but THIS service's
cgroup (user-runtime-dir@957.service under the new user-957.slice) isn't
completing. NEXT: log the cgroup abs_path + populated transition in
notify_events/task_exited (or check whether CLONE_INTO_CGROUP placement landed
the child in the SERVICE cgroup vs falling back to parent inheritance — if the
path resolve failed, the service cgroup never went populated and systemd's
oneshot cgroup wait is confused).

LATENT BUG found (separate): PidFdFile::poll_readiness keys ONLY on the `exited`
flag, not the live zombie state. A pidfd minted then `forget_pid`'d before its
process exits (seen: sibling pid 17 / later pids 9,10 with pidfd_found=false)
leaves the flag unset forever → that pidfd is permanently un-signalable. Worth
hardening poll_readiness to also consult the real task state.

### pidfd hang-pattern FIXED + cgroup-empty check DONE (2026-08-16)

1. pidfd hang pattern FIXED (commit 06b668e4): PidFdFile::poll_readiness now
   consults the target's real task state via the reuse-safe TaskId
   (task::task_has_exited: zombie or gone), not just the `exited` cache. A
   missed notify_exit no longer strands a pidfd un-signalable. Test:
   smoke_pidfd_authoritative_exit_fallback. userspace/process 60 pass.

2. cgroup-empty check DONE (diagnostic commit cb51d691, `cgevt_trace` cmdline):
   the user-runtime-dir@957 ExecStart child ATTACHES to its SERVICE cgroup
   (CGATTACH ok=true), the cgroup goes populated 0->1 then 1->0 on exit, and
   the ancestor user-957.slice follows. So the cgroup-empty completion signal
   FIRES correctly — NOT the blocker.

**CORRECTION: user-runtime-dir@957 was NEVER stuck.** The "start running" I
kept seeing was a `systemctl list-jobs` snapshot at log line 5848, taken LONG
before the child exited (its cgroup 1->0 is at line 9896). Both completion
signals (pidfd reap + cgroup-empty) fire. And downstream, `user@957.service`
(the systemd --user manager) DID start — `CGATTACH pid=4 .../user@957.service
ok=true`. So the user session is progressing.

NEXT FRONTIER: whether user@957's `systemd --user` manager (Type=notify) reaches
READY and starts the plasma session units (kwin), or stalls. The 300s boot
window ended before kwin. Repro: boot with the localed sandbox drop-in; trace
`trace_comm=systemd$` (or the plasma user units) to watch the systemd --user
startup and the plasma-kwin_wayland unit.

### Tracing toward kwin: a SECOND stall past locale1 (2026-08-16)

With the localed drop-in, the greeter's `locale1 GetAll` returns a VALID a{sv}
reply (localed works). The greeter then proceeds — loads its compositor libs
(kwindowsystem6, etc.) — and STALLS AGAIN before ever reaching StartUnit:
  - All 3 traced threads (startplasma-log main + QDBusConnection workers) did
    ~60k eventfd(fd8)+futex ping-pong syscalls EACH, then all park in ppoll.
  - It NEVER connects to the session bus (/run/user/957/bus) — so it is NOT
    waiting on systemd --user. It stalls BEFORE the session-bus
    KUpdateLaunchEnvironmentJob / StartUnit phase.
  - kwin_wayland is never execve'd (the greeter stalls before spawning it), so
    systemd --user's plasma units + kwin cannot be traced — the greeter is the
    gate.

This is the ORIGINAL Qt-internal cross-thread coordination stall characterized
early this session (main+workers wake each other via eventfd/futex, no
progress; "works on good rolls"). localed was a SEPARATE, earlier blocker;
fixing it advanced the greeter past locale1 and revealed this deeper stall.
Path to desktop needs BOTH cracked: (1) localed sandbox (drop-in workaround /
NARF fix TBD), (2) this Qt cross-thread stall (the hard, race-y one).
Trace: scratchpad/kwin_trace2.log.

### REFRAME: the "Qt cross-thread stall" is a systemd --user session-bring-up failure (2026-08-16)

Dug into the greeter's 2nd stall (past locale1). Chain of findings:

1. Added a diagnostic single-fd-infinite-park "spurious ret 0 after 2s" escape
   to poll.rs (now REVERTED). It fired 64x on the greeter's two threads but the
   greeter did NOT advance (no session bus, no kwin). => REFUTES the Qt
   wakeUp-elision hypothesis: the awaited event is GENUINELY NEVER POSTED, not a
   stuck-enqueued self-post. NARF eventfd/futex/ppoll are correct (fd4 rdy=0x4,
   counter genuinely 0 — no lost wake).

2. Greeter (startplasma-login-wayland, uid 957) connects ONLY to the SYSTEM bus
   (fd8), does Hello+locale1 (valid reply via drop-in), then goes fully idle in
   its main event loop. Its LAST file open is libsystemd.so.0 => it's at the
   systemd --user / session-bus step. It needs user@957's session bus to start
   its session components (kwin etc.). No /run/user/957/bus is ever created.

3. ROOT: `systemctl list-jobs` shows
     user-runtime-dir@957.service   start running   (stuck)
     user@957.service               start waiting   (blocked; After=runtime-dir)
   and NO `systemd --user` process. So the session bus never comes up => greeter
   idles forever. user-runtime-dir@957 is Type=oneshot (systemd-user-runtime-dir
   start 957); user@957 is systemd --user (Type=notify-reload).

4. cgevt_trace shows the cgroups DO go 0->1->0 (helper AND systemd --user
   processes run and exit), yet the START JOBS don't complete. Two variance
   modes: (mode 1, census boot) runtime-dir job stuck; (mode 2, cgevt boot)
   systemd --user starts then its cgroup empties (exits) => still no bus.
   => This is a start-job / process-exit DETECTION reliability problem
   (pidfd/cgroup-empty/SIGCHLD), same class as e971b210 / the kwin-wedge notes.
   NOT a Qt bug.

5. OBSERVER EFFECT confirmed: a --features syscall-trace boot never reached the
   user-session phase (crawled, and ananicy-cpp crash-looped 5x — 0x in light
   boots). Heavy syscall tracing changes the failure mode here; must diagnose
   this phase with LIGHT probes (cgevt_trace + a targeted pidfd/exit log), not
   the full firehose.

NEXT: nail ONE mode with a light probe — does PID1's exit-detection (pidfd
poll_readiness / cgroup.events inotify) fire for user-runtime-dir@957 / user@957
when their cgroup empties? The greeter is a red herring; fix the session-bus
bring-up and the greeter should proceed.

### ROOT CAUSE + FIX: CLOCK_REALTIME stuck at epoch 1970 (2026-08-16)

The greeter's session-bus stall root-caused to NARF's wall clock never being
anchored to the RTC at boot: CLOCK_REALTIME was boot-relative (epoch 1970).
systemd's timestamps read "Dec 31 1969"; PAM unix_chkpwd saw plasmalogin's
password "changed in future"; user@957 (systemd --user) session setup was
derailed -> no session bus -> greeter idled.

The kernel anchor (Linux read_persistent_clock equiv) had decayed to an empty
anchor_wall_clock_test_only(){} stub + orphaned doc comment; nothing called
set_wall_offset_uncapped at boot.

FIX (committed 94a35f26 + 1e59c53b):
- time/src/wall.rs: add wall_offset_ns() getter (+ re-export in time/src/lib.rs).
- frame/src/bare_main.rs: after TSC calibration, read CMOS RTC (rtc::read_now),
  set_wall_offset_uncapped(rtc_unix*1e9 - monotonic_ns). Single-threaded, before
  SMP wake-ups.
- userspace/src/vdso.rs: publish that offset into the vvar (was hard 0) so the
  vDSO CLOCK_REALTIME fast path reads real time too.
- (1e59c53b) CGATTACH/PIDFD-MINT/PIDFD-EXIT diagnostics moved from the heavy
  syscall-trace feature to the light cgevt_trace runtime gate.

VERIFIED: boots clean, systemd timestamps now "Aug 16 ... 2026", "password
changed in future" gone, plasmalogin DM starts. The 20x "Dec 31 1969" that
remain are just device-node mtimes (ls of /dev/dri/card0 etc.) — devtmpfs
created them pre-anchor; harmless.

OPEN / VERIFYING: whether the fixed clock lets user@957 (systemd --user) STAY
up + the greeter reach the session bus + kwin. Boots have big variance and go
quiet on the console once the greeter starts (output -> journal), so verifying
needs a greeter trace (trace_comm=startplasma-log) — in flight.

### Clock fix VERIFIED to help but NOT sufficient; systemd --user still exits (2026-08-16)

With the RTC clock fix (94a35f26):
- user-runtime-dir@957 completes cleanly (0->1->0).
- user@957 (systemd --user) now survives MUCH longer (~211 log lines vs ~6
  before) — the clock fix genuinely helped — BUT it STILL exits.
- Exact sequence (clockfix_cgevt.log ~L2204-2214): PIDFD-MINT pid=14 ->
  user@957 0->1 -> CGATTACH pid=14 -> init.scope 0->1 -> PIDFD-EXIT pid=14
  found=true -> init.scope 1->0 -> user@957 1->0. So systemd --user starts,
  sets up ONLY init.scope, then exits before starting ANY session service
  (no dbus, no kwin). PID1 DOES detect the exit (pidfd found=true).
- Greeter (traced) still parks after config-loading (plasma-localerc) — still
  no session bus to proceed to.

So the clock was ONE real blocker (fixed) but user@957 has a SECOND exit cause,
invisible on the console (systemd --user logs to the user journal). Repeated
pid=2 crash-exits (found=false) cluster around user@957's brief life — possibly
a helper fork it spawns that crashes, taking systemd --user with it.

Also surfaced (separate NARF gaps, not the blocker):
- devtmpfs chown unsupported: systemd-udevd "Failed to set owner/mode of
  /dev/{nvme0,sata0,vblk0,dri?} ... Operation not supported". Could later block
  GPU access if /dev/dri/card0 can't become root:video 0660.
- devtmpfs symlinks: "Failed to create device symlink /dev/disk/by-uuid/... ,
  /dev/rtc ... Invalid argument".

NEXT: trace systemd --user (pid 14, comm "systemd" — collides with PID1; filter
by pid/cgroup) to see WHY it exits right after init.scope. That is the true gate
to the session bus -> greeter -> kwin -> desktop.

### Tracing exhausted; need systemd --user's own log (2026-08-16)

Chased the userdb angle: user@957 (systemd --user) runs ~370ms during heavy
userdb (io.systemd.DynamicUser/Multiplexer) traffic, then exits voluntarily
(no fault, no reportable syscall error). Tracing the userdb SERVERS showed a
13772x accept4 "storm" on the socket-activation fd 3 — BUT ~85 accept4 actually
SUCCEED (=fd 6) and the rest are blocking-accept backstop re-checks (10ms)
INFLATED by syscall-trace. So the userdb server is HEALTHY; the storm was an
observer-effect artifact (again). systemd --user's exit reason is NOT visible
via syscalls.

Blocked on observability: systemd --user logs to the USER journal, not the
system console; its comm ("systemd") collides with PID1 so trace_comm can't
isolate it; and heavy tracing changes the failure mode. NEXT: capture systemd
--user's own log — e.g. an image drop-in for user@.service:
  [Service]
  Environment=SYSTEMD_LOG_LEVEL=debug
  StandardError=journal+console
so PID1 forwards its stderr (at debug) to the console. Durable image write =>
needs approval, like the localed drop-in.

STATE: clock fix committed (94a35f26, 1e59c53b) — real + independent value.
user@957 still exits ~370ms in; that is the true gate to the desktop.

### BREAKTHROUGH: (sd-mkuserns) hangs → SIGKILL loop = the real gate (2026-08-16)

Built a light USEREXIT probe (cgevt_trace-gated) in sys_exit_group.rs (exit_group
code) + terminate_current_task (killed_by_signal), filtered to comm=="systemd"
|| "(sd*". It revealed:
- systemd's USER-NAMESPACE setup helper "(sd-mkuserns)" is SIGKILL'd (signal 9)
  EVERY time, ALL at the identical ip=0x409000a4c14e, ZERO clean exits (11/11).
  systemd spawns it, it hangs during userns setup, systemd SIGKILLs it after a
  timeout, retries -> loop. Other helpers ((sd-rmrf),(sd-chown),(sd-gens)) exit 0.
- This user-namespace hang is almost certainly the root of the userdb/DynamicUser
  churn AND user@957 failing (RuntimeDirectory=/DynamicUser= services need userns).

NARF HAS userns support (sys_unshare CLONE_NEWUSER, namespaces.rs uid_map/gid_map/
setgroups, sys_ioctl.rs:356 PIDFD_GET_*_NAMESPACE for is_idmapping_supported).
So it's a mid-sequence hang, not a missing syscall.

Tracing trace_comm=(sd-mkuserns showed ONLY the prctl(PR_SET_NAME) return then
nothing until SIGKILL — trace_comm can't see before the comm is set, and SMP=2
serial output is interleaved/garbled. Re-tracing at SMP=1 for a clean stream to
see the exact hang syscall (or whether it even hangs at SMP=1). ip offset ~0xa4c14e
into a lib near 0x40_9000_0000 (likely libsystemd-shared).

PROBE IS UNCOMMITTED (sys_exit_group.rs + core.inc.rs terminate_current_task,
cgevt_trace-gated). Keep or commit as diagnostic infra.

================================================================================
DURABLE PER-FD READINESS + LINUX-TTWU WAKE REWRITE  (design record, 2026-08-17)
================================================================================

## How we got here
Greeter (plasmalogin) stall root-caused via syscall-trace (trace_comm=plasmalogin,
--features syscall-trace, KVM+-cpu host): the greeter child (plasmalogin-hel ->
startplasma-login-wayland --greeter, uid 957) busy-appears-stuck on
  ppoll(6 fds, timeout=NULL) = 0 (st=InvalidOp)   x886
polling its systemd userdb/Login sockets (/run/systemd/userdb/io.systemd.Multiplexer,
io.systemd.Login, io.systemd.DynamicUser). st=InvalidOp value=0 is the trace's
OWN marker for a PARKED, re-executing syscall (userspace/src/syscall.rs:3561:
"A park re-executes with exactly invalid_op()"). So ppoll is CORRECT (it parks);
the reply just never arrives ready. ppoll audited against Linux fs/select.c
do_poll: semantics match (NULL=block, {0,0}=nonblock, fd-resolved-once, EINTR,
ERR/HUP/NVAL always). The greeter's real blocker is upstream (user@957 session /
userdb reply, ECONNREFUSED on a socket-activated systemd socket) - separate task #31.

BUT the ppoll audit surfaced a real, independent Linux-divergence worth fixing:
NARF's poll/epoll WAKE is best-effort (readiness::notify) + a ~10ms backstop as
the CORRECTNESS floor; Linux's per-fd wait-queue wake IS the guarantee. User wants
this closed end-to-end, durable, enforced by Rust semantics, no hacks.

## The bug CLASS (what we eliminate)
Old FileOps readiness = THREE drift-prone methods: poll_readiness (level) +
poll_edge_token (edge) + readiness_notifies (a hand-maintained "do I even notify"
bool) + free-fn narf_net::readiness::notify. Any pair out of sync = a lost wake
or a busy-spin. readiness.rs itself documents notify as best-effort
("no correctness dependency on it - only latency"), backstop = the floor.

## Landed: the Readiness primitive  (commit 40532a1a, lib/src/readiness.rs)
One owned per-fd cell; makes the lost-wake race UNREPRESENTABLE, not guarded:
  struct Readiness { inner: IrqSafeSpinLock<Inner> }
  Inner { mask:u32, seq:u64, waiters: BTreeMap<u64 id, Waiter{interest,waker}> }  // waiters PRIVATE
  set(add,clear): only mutator; on rising edge bump seq + wake+remove intersecting waiters, under lock
  arm(id,interest,&waker) -> Poll<u32>: only registrar; checks mask FIRST under the SAME lock, else registers
  disarm(id), mask(), seq(), waiter_count()
Three properties => class gone by construction:
  1. waiters private + arm is sole inserter + arm always checks first  => cannot register without checking
  2. set wakes under the SAME lock as arm's check => arm-vs-set serialized => no lost wake either race order
  3. waking intrinsic to every set (no notifies bool); mask+seq move together (no edge/level desync)
Host-tested 6/6 (cargo test -p narf-lib readiness): arm-then-set, set-then-arm,
interest respected, re-arm dedups, seq only on rising edge, disarm prevents stale wake.

## End-to-end durability analysis (the TTWU path)
Is the delivered wake itself durable? Chased it:
  - park registers the REAL executor waker (user_task.rs:770 register_io_waiter(task_id, waker.clone()))
  - wake_one(task_id,w): uc.sleep_deadline_ns.store(0) + w.wake()
  - the executor waker = Arc<WakeCell{flag:AtomicBool, cpu:AtomicU32}> (scheduler/src/lib.rs:1861 make_waker, TASK_VTABLE)
  - wake_raw:    flag.store(true) + resched_remote(cpu) + DROPS the Arc (by value)
  - wake_by_ref_raw: flag.store(true) + resched_remote(cpu), NO drop
  - run_until_empty scans the flag bit == Linux runqueue scan
KEY: flag.store(true)+resched_remote IS Linux TTWU (set RUNNABLE + kick CPU), and
it is IRQ-safe + lossless via wake_by_ref (no Arc drop). The ONLY non-durable link
is the Arc DROP (wake-by-value): dropping the last Arc<WakeCell> in IRQ = slab
dealloc = illegal in IRQ (scheduler/src/lib.rs:2490,2564) => those paths defer the
WHOLE waker (incl the flag store) through narf_lib::deferred_wake, a BOUNDED
per-CPU queue that DROPS ON OVERFLOW ("recoverable via next timer tick") = the
backstop. Overflow loses the flag store = loses the wake.

## The end-to-end durable fix (Linux-TTWU-like)
1. Readiness/IRQ wake fires wake_by_ref (the runnable-bit store), NEVER wake-by-value.
   Flag set immediately, durably, IRQ-safe. No deferral of the WAKE.
2. Arc reclamation leaves IRQ: the Arc<WakeCell> is only DROPPED in task context.
   Registrations torn down on task exit (disarm-on-exit) so a Readiness cell never
   holds the last ref at wake time. deferred_wake stops being load-bearing for wakeups.
3. Optional cleaner form: a stable ttwu(task_id) on the scheduler (WakeCell
   addressable by task id) so Readiness wakes without holding a Waker clone at all.

## Refinement OWED to the landed primitive (40532a1a)
Readiness::set currently calls waker.wake() (by value) AND removes+drops the fired
waiter inside set -> both are IRQ-UNSAFE. Cycle 2 fix:
  - set fires waker.wake_by_ref() (flag store, no drop)
  - set does NOT drop a fired waker (keep it registered; re-arm replaces by id;
    exit disarms) so set is safe from an IRQ readiness source
  - add race/IRQ-safety tests

## Cycles
1. [DONE 40532a1a] Readiness primitive + host tests; [DONE dd196eec] spec doc.
2. Refine Readiness::set -> wake_by_ref, no drop-in-set (+ tests).  <-- NEXT
3. Scheduler: stable ttwu(task_id) (WakeCell by id) + disarm-on-task-exit hook.
4. Migrate FileOps: poll_readiness/poll_edge_token/readiness_notifies -> owned
   Readiness cell; convert the ~36 narf_net::readiness::notify(0) sites (audit:
   mqueue, io_mux/eventfd, pipe, perf_event, pidfd, socket all variants, evdev,
   on_child_exit already notify; tty/signalfd/etc likely silent).
5. Rewire poll_common + epoll_wait_common park -> arm/disarm; INSTRUMENT the 10ms
   backstop to prove it never fires, then DELETE it.
6. Boot-verify (greeter path hammers poll/epoll).

## Key refs
lib/src/readiness.rs (primitive), userspace/src/poll.rs:486 poll_common (park path),
userspace/src/handlers/core.inc.rs:150 register_io_waiter / :189 wake_io_waiters /
:310 no-op raw_waker (NOT the executor waker), scheduler/src/lib.rs:1795 TASK_VTABLE
/ :1861 make_waker / :2161+ deferred_wake drain, net/src/readiness.rs (old global
gen+hook, to be subsumed), filesystem/src/lib.rs:719 FileOps poll_readiness /
:738 poll_edge_token / :773 readiness_notifies (to be replaced by one readiness()).

--- UPDATE 2026-08-17: cycle 2 DONE (commit 060b7ad3) ---
Readiness::set now fires waker.wake_by_ref() UNDER the lock, never removes a
waiter (drop-free). resched_remote verified LOCK-FREE (scheduler/src/lib.rs:
atomics + fn-ptr IPI hook, no .lock()) so wake-under-lock is safe + Linux-like.
Host-tested 7/7 (added set_is_drop_free_and_keeps_waiter).

CONSEQUENCE: cycle 3 (separate scheduler ttwu(task_id) / WakeCell-by-id) is
SUBSUMED. The poll park path already hands arm() the real executor waker
(Arc<WakeCell>, wake_by_ref = flag.store+resched = Linux TTWU). set()'s
wake_by_ref IS the durable ttwu; no Waker->id redesign needed. The only Arc
drops left are in arm(replace)/disarm/BTreeMap ops, ALL task-context (poll
syscall path) => IRQ-safe. Remaining lifetime concern = task exit / fd close
must disarm the task's Readiness registrations (cleanup, not a wake bug) ->
folds into cycle 5.

REVISED remaining cycles:
  3. (subsumed - skip)
  4. Migrate FileOps -> owned Readiness cell; convert ~36 notify(0) sites.  <-- NEXT
  5. Rewire poll_common + epoll_wait_common park -> arm/disarm; disarm on
     poll-exit / fd-close / task-exit; instrument the 10ms backstop to prove it
     never fires, then delete it.
  6. Boot-verify (greeter path hammers poll/epoll).

--- UPDATE 2026-08-17: cycle 4 STARTED (commit 114ffac1) ---
Added FileOps::readiness() -> Option<&narf_lib::readiness::Readiness> (default
None). Additive/non-breaking; narf-filesystem builds clean. None = legacy path,
so descriptors migrate one at a time.

POLL-LAYER INTEGRATION DE-RISKED:
  - poll_common has the fd set but NOT a Waker; the generic park machinery
    (user_task.rs:692 park_should_block, :770 register_io_waiter) has the Waker
    but not the poll fd set. Bridge: narf_scheduler::stackful::current_stackful_waker()
    (already used from userspace/src/user_task.rs:986, core.inc.rs:6585) returns
    the current task's Arc<WakeCell> waker -> poll_common/epoll_wait_common can
    fetch it and arm() directly.
  - Wiring: at park, for each fd whose readiness() is Some,
    arm(task_id, events_interest, &waker). On every return path (ready/timeout/
    EINTR) disarm(task_id) each. Re-arm on re-execute is idempotent (dedup by id).
    With NO fd migrated it's a pure no-op (all readiness()==None).
  - poll_common park insertion point: userspace/src/poll.rs ~768 (where
    net_io_wait.store(true) + record_poll_wait happen); epoll twin in epoll.rs.

NEXT (fresh cycle, hot-path, boot-verify):
  4b. Wire poll_common + epoll_wait_common arm/disarm (additive, no-op until
      migration) -> compile + boot-smoke (identical behavior).
  4c. Migrate FIRST fd type (eventfd io_mux.rs or pipe pipe.rs: own a Readiness
      cell, route reads/writes/close through cell.set(add,clear), return
      Some(&cell) from readiness()) -> boot-verify the durable arm-wake fires
      (redundant with the legacy notify during migration = safe).
  4d. Migrate the rest (AF_UNIX socket = greeter path, inet, mqueue, tty,
      signalfd, ...); convert the ~36 notify(0) sites to cell.set().
  5.  disarm on poll-exit/fd-close/task-exit; instrument then DELETE the 10ms
      backstop; boot-verify.

--- UPDATE 2026-08-17: durability detail for the poll-layer arm wiring ---
CRITICAL: the arm loop IS the register-then-recheck. arm(task_id, interest, &w)
returns Poll::Ready(revents) if the fd became ready in the poll_scan->arm window
(the classic lost-wake window). So arm_readiness_cells must return "any fd went
Ready" and, if so, the park is ABORTED: disarm all + let the syscall re-execute
(re-scan finds it ready and returns). Mirror the existing epoll pattern at
userspace/src/poll.rs:775-784 (epoll_fd_has_ready -> one immediate re-execution
instead of relying on the backstop). During migration (no cells) arm returns
Pending for nothing -> any_ready=false -> legacy park unchanged.
This recheck is why the wake is durable end-to-end without the backstop: edge
before arm -> caught by arm's Ready; edge after arm -> caught by set()'s
wake_by_ref on the registered waiter. No window.

--- UPDATE 2026-08-17: cycle 4b DONE + VERIFIED (commit 3270580c) ---
poll_common park now arms/disarms FileOps::readiness() cells (arm = register-
then-recheck; abort park if any cell fd went Ready in the scan->arm window;
disarm on ready/timeout/EINTR returns). Waker via
narf_scheduler::stackful::current_stackful_waker(). Additive no-op until an fd
migrates. Helpers: arm_readiness_cells / disarm_readiness_cells (userspace/src/poll.rs).
BOOT-VERIFIED: xtask test --features cgroup,container,linux-compat --subsystem
syscall_abi = 1130 pass / 0 fail / 0 skip, clean exit, every poll/ppoll/pselect/
epoll test OK, 0 FAIL anywhere.
NEXT = 4c: migrate first fd type (pipe pipe.rs OR eventfd io_mux.rs): add a
narf_lib::readiness::Readiness to the shared state, route read/write/close ->
cell.set(add,clear) (keep the legacy readable_token/notify during migration =
belt+suspenders), return Some(&cell) from readiness(). Then boot-verify the
durable arm-wake fires. NOTE epoll_wait_common still needs the SAME arm/disarm
wiring as poll_common (twin) before epoll-parked fds get the durable path.

--- UPDATE 2026-08-17: rebase onto origin/main DONE + cycle 4b-twin + eventfd migration ---
REBASE: cachyos-efi rebased onto origin/main (2264a675), 111 commits, 4 conflicts
resolved (safety-argument.toml keep-both x2, frame/bare_main.rs kswapd_wake vs
kswapd_pump design-supersession + DISTRO_WRITABLE_RUNTIME_MOUNTS graft,
memory/tests.rs keep-both nested_fork + vdso_cow tests, bare_main cmdline args()
+ kernel_exclude). Post-rebase API-drift fixup: proc_task_info gained a
TaskInfoQuery arg (Vmas for fault-vma diag, Basic for 2 ctty tests). VERIFIED:
full kernel builds clean, boot-smoke clean exit, boot/args 8/0. All session work
intact (new hashes).
CYCLE 4b-twin [committed 6608b630]: epoll_wait_common arms/disarms interest-fd
Readiness cells (via item.file.upgrade().readiness()). CONSERVATIVE: registration
only, NO arm-Ready park-abort (epoll is ET; a level-ready-no-edge fd would
livelock collect_ready). Delivery stays with collect_ready + epoll_park_gen guard
(legacy notify covers the race during migration); the cell adds the durable wake.
CYCLE 4c [committed <eventfd>]: EventFd migrated - owns a Readiness cell (POLL_IN=
counter>0, POLL_OUT=counter<MAX-1), sync_readiness() republishes on every counter
change, readiness()->Some. Keeps legacy tokens+notify(0) belt+suspenders. FIRST
fd on the durable path. Boot-verifying syscall_abi (poll/epoll/eventfd).
NEXT: 4d migrate pipe/AF_UNIX(greeter)/mqueue/tty/signalfd + convert notify(0)
sites; 5 disarm-on-exit/fd-close + delete the 10ms backstop.
--- UPDATE: cycle 4c eventfd VERIFIED: syscall_abi 1130/0/0, clean boot, all poll/epoll green ---

--- UPDATE 2026-08-17: AF_UNIX migration design (cycle 4d, the greeter path) ---
AF_UNIX is the hard fd: SocketFile.state (IrqSafeSpinLock<SocketState> w/ rx/tx
Arc<RingBuf>) is BEHIND A LOCK, so readiness()->&Readiness (a borrow) can't reach
the ring. Also dgram_readable_token / listener_readable_token are direct fields.
DESIGN (Option A, cleaner than plumbing cells cross-endpoint): add a general
FileOps method
    fn arm_readiness(&self, task, interest, &waker) -> Option<Poll<u32>>   (default: readiness().map(|r| r.arm(...)))
    fn disarm_readiness(&self, task) -> bool                                (default via readiness())
Rewire poll_common + epoll_wait_common arm/disarm helpers to call
ops.arm_readiness / ops.disarm_readiness (eventfd keeps working via the default).
RingBuf gets its OWN Readiness cell (POLL_IN=non-empty, POLL_OUT=has-space),
synced by RingBuf write/read (NO cross-endpoint plumbing - the ring is shared, so
B armed B.rx's cell and A's write sets B.rx's cell). SocketFile::arm_readiness
locks state; Connected -> arm rx.cell (interest&POLL_IN) + tx.cell
(interest&POLL_OUT). dgram/listener stay legacy for now. NOTE: greeter reply
never arrives (task #31, upstream) so this is the wake-divergence rewrite, NOT
the greeter fix.
SUBSTEPS: (1) arm_readiness contract + rewire poll/epoll [additive, no behavior
change]; (2) RingBuf cell + sync; (3) SocketFile override; boot-verify each.

--- UPDATE 2026-08-17: AF_UNIX migration IMPLEMENTED (cycle 4d, sub-steps 2+3) ---
Sub-step 1 (arm_readiness/disarm_readiness FileOps contract + poll/epoll rewire)
already landed 3975a0c3. This session did 2+3:

SUB-STEP 2 — RingBuf durable cell (socket.rs):
  - Added `readiness: narf_lib::readiness::Readiness` field to RingBuf. A ring is
    SHARED (one endpoint's rx == the peer's tx), so its cell carries the FULL
    triple: POLL_IN(data-or-closed) | POLL_OUT(has-space) | POLL_HUP(closed). The
    reader arms POLL_IN|POLL_HUP; the writer arms POLL_OUT — SAME cell — so a
    write that fills the ring wakes the reader and a read that drains it wakes the
    writer, with ZERO cross-endpoint plumbing.
  - new() inits Readiness::new(POLL_OUT) (empty = writable, not readable).
  - sync_readiness(): re-reads inner (has_data / has_space) + closed, computes the
    absolute mask, calls set(add, clear). Re-lock (not captured locals) = always
    reflects reality at publish time; a transient stale clear self-corrects on the
    next op, and close()'s "set closed THEN sync" ordering guarantees the final
    POLL_IN|POLL_HUP rising edge is never lost.
  - Synced at every occupancy change: write / write_stream_with_fds /
    write_packet_with_fds (n!=0), read / read_packet (record consumed), close
    (latches POLL_IN|POLL_HUP). Legacy readable/writable tokens + wake_reader kept
    belt+suspenders during migration.

SUB-STEP 3 — SocketFile::arm_readiness / disarm_readiness (FileOps override):
  - Connected (Unix/Inet/Inet6): clone rx/tx Arcs under state lock, RELEASE the
    lock (temp guard drops at the `let ... = match ...;` semicolon), then arm off
    the lock. want_in -> rx.arm(POLL_IN|POLL_HUP); want_out -> tx.arm(POLL_OUT|
    POLL_HUP). POLL_HUP folded into BOTH so a peer close (which closes the peer's
    rings = OUR rx via its tx AND OUR tx via its rx) wakes reader AND writer, even
    one blocked on a full ring. Union the Ready bits; Some(Ready) if any, else
    Some(Pending).
  - Returns None for interest touching neither dir, and for dgram/listener/netlink
    states -> caller keeps legacy edge-token + 10ms backstop.
  - Lock order: {state->cell} and {inner->cell}; cell ALWAYS innermost -> no cycle.

TESTS: readiness.rs 7 host fusion tests still green (the arm/set no-lost-wakeup
proof). Added ABI regression smoke_abi_socket_connected_pair_peer_close_reports_hup
(peer close -> generation wake + POLLIN|POLLHUP re-scan). HONEST GAP: single-thread
ABI tests CANNOT reach arm_readiness — poll_scan and the cell agree by
construction, so the park path is never entered when data is present; the fusion
is only distinguishable under concurrency (parked reader woken by concurrent
writer) => validated by the readiness host tests + BOOT, not a socket unit test.
Both compile clean (userspace --features cgroup and cgroup,linux-compat).
NEXT: boot-verify syscall_abi/socket, then CachyOS; then migrate pipe/mqueue/tty/
signalfd + convert remaining notify(0) sites; cycle 5 disarm-on-exit/fd-close +
instrument-then-delete the 10ms backstop.

--- VERIFIED 2026-08-17 [committed cf6dce49]: AF_UNIX cycle 4d done ---
syscall_abi/socket 118 pass / 0 fail / 0 skip (incl. new peer_close_reports_hup),
kernel cleanly exited, no panic markers. readiness.rs 7/7 host fusion tests green.
Connected AF_UNIX/AF_INET stream now on the durable per-fd cell. dgram/listener/
netlink still legacy. REMAINING 4d fd types: pipe, mqueue, tty, signalfd + ~36
notify(0) call sites. CYCLE 5: disarm-on-exit/fd-close + instrument-then-delete
the 10ms backstop. NOTE: pipe/mqueue/tty are NOT on the desktop critical path;
the AF_UNIX path (D-Bus/Wayland) was the desktop-relevant one. Task #31 (greeter
user@957 session activation) remains the actual visible-desktop blocker (upstream
userdb/session, not a wake bug).

--- VERIFIED 2026-08-17 [committed bd4c33a8]: pipe cycle 4d done ---
Full syscall_abi 1101 pass / 0 fail / 0 skip (incl. new pipe_peer_close_wakes_
parked_poller), clean exit. Pipe = SIMPLE case: PipeShared reachable via Arc (no
lock), so plain readiness()->Some(&shared.readiness) on both halves; default
arm_readiness delegates. One shared cell, union mask POLL_IN|POLL_OUT|POLL_HUP|
POLL_ERR; poll AND epoll layers fold ERR|HUP into arm interest (poll.rs:502,
epoll.rs:322) so a full-pipe writer wakes on reader-close. REMAINING 4d: signalfd,
tty/pty, mqueue (survey which are real parkable FileOps first). Then CYCLE 5:
disarm-on-exit/fd-close + instrument-then-delete the 10ms backstop (needs ALL
parkable fd types migrated first).

--- 2026-08-17: remaining fd-type landscape (post pipe) ---
Surveyed the rest. They are NOT all the clean pipe/eventfd shape:
  SIMPLE local-buffer produce-site (like pipe): mqueue (mqueue.rs), uinput
    (io_mux/linux_compat) — LOW traffic, low desktop value.
  CROSS-MODULE produce-site (bigger, riskier):
    - signalfd: readiness = per-task SIGNAL_PENDING & mask; produce site is
      raise_signal_pending/_irq in handlers/compat.inc.rs (bumps
      SIGNAL_READABLE_GEN, calls wake_signal). FINDING: wake_signal
      (core.inc.rs:46) ALREADY targeted-wakes — clears an infinite
      sleep_deadline (MAX->0) so epoll_wait(-1)/poll(-1) on a signalfd wakes,
      and fires the task's SIGNAL_WAKER. So the high-value infinite-wait case is
      NOT purely backstop-bound; a durable cell here needs a park/wake-path
      analysis (poll parks under IO_WAKER, not SIGNAL_WAKER) + a per-task
      readiness registry the signal producer can set(). Its own cycle.
    - timerfd: produce site = timer expiry; already uses poll_deadline() to
      clamp the park to the deadline (scheduler wakes at expiry). Durable-ish
      already; cell would need a timer-expiry set() hook.
  NO pty in NARF (PtyMaster is only in "same class as" comments).
DONE (high-value, clean, boot-verified): AF_UNIX stream, pipe, eventfd.
Backstop deletion (cycle 5) needs ALL parkable types; signalfd/timerfd are the
gating hard ones and deserve focused cycles, not a mechanical grind.

--- 2026-08-17: signalfd durable-wake ANALYSIS (cycle: signalfd) ---
CODE REVIEW FINDING: signalfd is ALREADY durably woken for the real workload —
it does NOT depend on the 10ms backstop the way pipe/AF_UNIX/eventfd did.
  Producer: raise_signal_pending (compat.inc.rs:~4400) sets the SIGNAL_PENDING
    bit and calls wake_signal(task) UNCONDITIONALLY (line 4415), on EVERY raise.
  wake_signal (core.inc.rs:46): clears an infinite sleep_deadline (MAX->0) AND
    fires the task's SIGNAL_WAKER.
  Consumer park: park_should_block (user_task.rs:692) covers "sleep/nanosleep/
    pause/blocking poll·epoll·futex" and, for every non-sigwait park, registers
    the SAME stackful park waker in SIGNAL_WAKERS (line 760) then rechecks
    pending (761). => a signal raised AFTER park registration fires the
    SIGNAL_WAKER => the parked poll/epoll resumes => re-scans => signalfd
    poll_readiness (pending_in_mask, mask-filtered) => ready. TARGETED + durable.
RESIDUAL GAP (the only one): the poll_scan->register window. The recheck at
  user_task.rs:761 uses is_signal_pending = (pending & !SIGNAL_MASK) != 0 —
  BLOCK-FILTERED. But signalfd reads BLOCKED signals (canonical use: block
  SIGCHLD, read via fd; pending_in_mask uses raw signal_pending_of, no block
  filter). So a BLOCKED signal raised in the scan->register window is missed by
  the recheck, and its pre-registration wake_signal fired into no waiter ->
  falls to the <=10ms backstop. Bounded latency, NOT a strand (today).
WHY NOT a per-task/per-fd Readiness cell: a task-global POLL_IN cell CONFLATES
  signals — arm() would return a false Ready for a signalfd whose watched signal
  isn't pending while an unrelated signal is stuck pending => poll returns 0
  events on an infinite wait => BUSY SPIN. Correct cell would be per-signalfd +
  a per-task registry the producer iterates (IRQ-safe, alloc-free) — large.
DURABLE FIX (minimal): a per-task RAISE generation (bump on EVERY raise, not just
  was_empty like SIGNAL_READABLE_GEN which also feeds the EPOLLET edge token) +
  a register-then-recheck in the poll/epoll park guarding on it — the exact
  shape of the net-readiness guard (refresh_io_wait_generation_after_
  registration + epoll_park_gen, user_task.rs:684/771). Edge (generation), not
  level (raw pending), so a STANDING blocked-pending signal with no signalfd
  does NOT spin: only a raise-since-scan re-execs, and the re-exec re-scans +
  re-parks if nothing is actually ready.
DECISION POINT: this is a SCHEDULER-level change (park guard) whose observable
  effect is ZERO until the 10ms backstop is deleted (cycle 5) — the backstop
  masks the window today. Landing it now adds boot risk for no current
  behavior change; it belongs WITH cycle-5 backstop deletion, where the guard
  framework is revisited wholesale. Recommend DEFER to cycle 5 (tracked), not a
  standalone risky scheduler edit now.

--- 2026-08-17: signalfd durable guard IMPLEMENTED (cycle: signalfd) ---
Chose the per-task RAISE-generation park guard (not a Readiness cell — a cell
conflates signals -> false-Ready -> spin). +135 lines, 7 files, no deletions.
  compat.inc.rs: static SIGNAL_RAISE_GEN (SignalBitsTable) + pub
    signal_raise_generation(task); bump on EVERY raise in raise_signal_pending
    (update_or_init) AND raise_signal_pending_irq (update_existing, alloc-free,
    seeded by ensure_signal_pending_slot); cleared in signal_init +
    __test_signal_reset.
  core.inc.rs: signal_bits_remove(&SIGNAL_RAISE_GEN, tid) at task-exit.
  user_task.rs: UserTaskCtx.signal_park_gen field; the GUARD in park_should_block
    (inside the net_io_wait block, after register_signal_waker+register_io_waiter):
    if signal_park_gen != signal_raise_generation(task) && signal_pending_of(task)
    != 0 -> advance the snapshot, drop both wakers, clear deadline, return false
    (re-exec). Edge not level (standing blocked-pending signal doesn't spin);
    snapshot-advance-on-fire makes non-re-snapshotting net_io_wait parks (socket
    recv) spin-safe.
  poll.rs / epoll.rs / mqueue.rs: snapshot signal_park_gen = signal_raise_
    generation before the scan, beside the existing epoll_park_gen snapshot.
WHY it works: post-park raises already wake via wake_signal->SIGNAL_WAKER (the
  same stackful park waker, registered at user_task.rs:772). The ONLY hole was
  the scan->register window for a BLOCKED signal (is_signal_pending block-filters
  it). The raise-gen (block-agnostic, every-raise) + register-then-recheck closes
  it, mirroring the net-readiness / futex_park_gen guards.
TEST: smoke_abi_signal_raise_generation_bumps_every_raise — pins the crux
  invariant (gen advances on a SECOND signal while a first is pending, not just
  was_empty). The fused wake itself is only distinguishable under concurrency ->
  host/boot, like every other fusion case. Compiles clean (cgroup and
  cgroup,linux-compat). Boot-verifying full syscall_abi now.

--- VERIFIED 2026-08-17 [committed 0cf398b0]: signalfd guard done ---
Full syscall_abi 1102 pass / 0 fail / 0 skip (incl. new raise_generation_bumps_
every_raise), clean exit, no panics. Scheduler park-path change regressed
nothing (poll/epoll/signal/futex/mqueue parks all green). signalfd scan->register
window CLOSED for backstop deletion. Session cycle-4d/signalfd tally: AF_UNIX
stream (cf6dce49), pipe (bd4c33a8), signalfd guard (0cf398b0); eventfd was prior.
REMAINING for cycle-5 backstop deletion: timerfd (poll_deadline-based, needs a
timer-expiry hook), mqueue/uinput (simple local-buffer), netlink replies, AF_UNIX
dgram/listener, AF_INET dgram/raw/TCB. Then instrument-then-delete the 10ms
backstop.

--- 2026-08-17: session wrap (durable-wake) + fmt note ---
Committed this session on cachyos-efi:
  3975a0c3 readiness arm/disarm FileOps contract (prior)
  cf6dce49 AF_UNIX stream durable cell
  bd4c33a8 pipe durable cell
  0cf398b0 signalfd scan->register lost-wake guard
  106cd956 rustfmt reflow of the above + proc_task_info fixup
All boot-verified (syscall_abi 118/1101/1102 respective, clean exits).
FMT DEBT (NOT mine, left untouched to avoid cross-session conflict):
  userspace/src/process_e2e_tests.rs + userspace/src/tests/epoll_poll.rs were
  committed UNFORMATTED by earlier branch commits (a099cb8d, bb8ad2db). They fail
  `cargo fmt --check`. Fix before the eventual main-merge (own commit), but they
  predate this session's work.
NEXT OPTIONS: (a) boot CachyOS end-to-end (cumulative durable-wake validation
  under real concurrency + regression check); (b) more fd migrations toward
  cycle-5 backstop deletion (timerfd needs an expiry hook; mqueue/uinput simple);
  (c) task #31 greeter user@957 session-activation (the actual visible-desktop
  blocker, upstream).

--- 2026-08-17: MIGRATION near-COMPLETE (session tally) ---
DONE — durable per-fd targeted-wake cell (all clean local-buffer produce sites):
  3975a0c3 arm/disarm FileOps contract
  cf6dce49 AF_UNIX/INET stream (connected)
  bd4c33a8 pipe
  (prior) eventfd
  0cf398b0 signalfd scan->register guard (per-task raise generation)
  8c18d689 pidfd, inotify, fanotify, perf_event  [parallel workflow, 3 agents]
  0b7b3804 AF_UNIX/INET dgram + AF_UNIX/INET/INET6 listener
  106cd956 rustfmt reflow
ALREADY DURABLE (no cell needed, verified): timerfd (poll_deadline clamps park
  to expiry), signalfd/SignalFdFile (the signal_park_gen guard is fd-agnostic),
  InetWired/TCB (tcb_owner targeted wake), InetConnected loopback (stream cell).
DEFERRED — all remain CORRECT today via notify(0) + the epoll_park_gen guard;
  only the herd->targeted OPTIMIZATION is undone:
  - netlink uevent: shared-broadcast source -> a targeted cell needs a per-fd
    subscriber registry (same shape as signalfd's). Herd notify is correct.
  - netlink reply queues (route/generic/...): SYNCHRONOUS (reply produced in the
    same syscall) -> no parked waiter to optimize.
  - InetRaw: rare.
  - POSIX mqueue: FileOps in filesystem/src/mqueuefs.rs (different crate).
  - console: readiness source in narf_filesystem::console_tty (different crate).
BACKSTOP-DELETION READINESS (cycle 5): every wake source now closes its
  scan->register window — local-buffer fds via cells (intrinsic), shared/sync
  fds via notify->epoll_park_gen, signals via signal_park_gen, timers via
  poll_deadline. The 10ms backstop SHOULD now be deletable; that is a separate
  risky audit+delete+boot step (instrument first, delete, boot-verify).

--- 2026-08-17: deferred-tail progress (mqueue + uevent) ---
POSIX mqueue [filesystem/src/mqueuefs.rs]: Readiness cell on Arc<Queue> (reachable
via MqueueFile.queue), Readiness::new(POLL_OUT); sync_readiness() recomputes
POLL_IN(non-empty)|POLL_OUT(<maxmsg); send/receive drop the state lock then sync;
MqueueFile::readiness()->Some(&queue.readiness) (default arm/disarm). Kept tokens
+ the notify(0) in the mqueue syscall handlers. Cross-crate but self-contained.

netlink uevent [socket.rs]: SHARED broadcast, so a per-fd cell needs a registry.
SocketFile gains uevent_readiness: Arc<Readiness>; a group-1 bind registers
Arc::downgrade into UEVENT_READINESS_SUBS; uevent_wake_hook sets POLL_IN on every
registered cell (pruning dead Weaks) BEFORE the kept notify(0) — a TARGETED wake
of just the parked monitors, not the whole io-waiter herd (SMP IPI-storm win on a
busy desktop). arm_readiness/disarm_readiness gain a Uevent case; poll_readiness
reconciles the cell against subscribed && reader.has_pending. Both compile clean;
boot-verifying syscall_abi (+container for mqueue/ipc).

STILL DEFERRED (documented, all correct via notify+epoll_park_gen):
  - console: input source is narf_input's global ring (shared with evdev, cross-
    crate); a console cell would fire on ALL input (routing-dependent), and a
    Wayland desktop barely parks on the console -> low value, deferred.
  - netlink reply queues (route/generic/...): SYNCHRONOUS, no parked waiter.
  - InetRaw: rare.

--- VERIFIED 2026-08-17 [committed 44366077]: mqueue + uevent tail done ---
syscall_abi (+container) 1133 pass / 0 fail / 0 skip, boot-smoke clean. All uevent
tests green. CONSOLE final call: NOT worth migrating — the input dispatch
(evdev_dispatch_wake) wakes for ALL input and must keep notify(0) for evdev, so a
console cell fired there gives NO herd reduction (would need input-routing logic
to fire only console pollers); a Wayland desktop barely parks on the console.
Deferred definitively. netlink-reply (synchronous) + InetRaw (rare) likewise.
MIGRATION COMPLETE for every meaningful parkable fd type. Session: 10 commits
(cf6dce49 bd4c33a8 0cf398b0 106cd956 8c18d689 0b7b3804 44366077 + prior 3975a0c3
2506f018 6608b630). All boot-verified. The 10ms backstop is now deletable
(cycle 5: instrument-then-delete, separate risky step).

--- 2026-08-17: BACKSTOP DELETION ATTEMPTED → BLOCKED (finding) ---
Instrument-first: removed the 10ms backstop (park_fire_deadline_ns → real
deadline) + booted syscall_abi with --features stall-watchdog. RESULT: STALL-WD
forward-progress PANIC (trap.rs:442). Diagnosis: NOT a missed produce-notify —
cpu0 ready_depth=14 all pops=0, every other CPU idle-halted, resched_ipi_sent=0,
wheel occ=0. The 10ms timer is ALSO A SCHEDULER HEARTBEAT that kicks halted CPUs
to run ready tasks; a targeted wake doesn't reliably resched a halted CPU alone.
Reverted (commit 4a57a6ad documents it in park_fire_deadline_ns). The fd
migration STANDS (redundant-as-lost-wake-net proven; deletion just needs the
wake→resched-IPI path fixed first — a separate scheduler change). Memory saved:
project_backstop_is_scheduler_heartbeat.

--- 2026-08-17: wake→resched fix ATTEMPT 2 (floor tick) → still blocked ---
Root-caused the backstop-removal stall: HPET pump (timer_pump.rs pump_irq)
re-arms ONLY from the wheel's next deadline; the backstop's per-park 10ms timers
were the only thing keeping the wheel non-empty → keeping the timer alive.
Hypothesis: the timer is a preemption heartbeat; a FLOOR TICK (always re-arm the
HPET at ≤10ms even when the wheel is empty) would replace it. Implemented floor
tick + re-removed backstop + booted with stall-watchdog. RESULT: BYTE-IDENTICAL
stall — cpu0 ready_depth=14 (cpu-0-pinned kernel tasks, awake, pops=0=NEVER
popped), rip=0x0/task=0/LAST_* unset (cpu0 took NO trap → spinning IF=0), wheel
occ=0, resched_ipi_sent=0. Identical-with-floor-tick DISPROVES the heartbeat
theory: a timer IRQ can't fire into an IF=0 spin. It's a scheduler
spin-with-interrupts-disabled that the wheel's non-emptiness masked — NOT a
missing tick/IPI. WHERE cpu0 spins + why it stops popping its own runnable pinned
slots is unknown (need cpu0's live RIP). NEXT: NMI the stuck CPU from the
stall-watchdog (NMI bypasses IF=0), record its RIP — data-first, not another
speculative timer edit. REVERTED both edits; tree green at 4a57a6ad. resched IPI
(VECTOR_RESCHED) itself is wired + fine (bare_main:903); it just wasn't exercised
(all work cpu-0-local). Memory updated: project_backstop_is_scheduler_heartbeat.

--- 2026-08-18: BACKSTOP DELETION BREAKTHROUGH (NMI probe → perf fix) ---
Built an NMI stuck-CPU probe (committed cabedc8c): the watchdog NMIs each
non-halted CPU (NMI bypasses IF=0) and records its interrupted RIP — LAST_RIP was
0x0 because the wedged CPU takes no traps. It pinpointed the "stall": cpu0 spinning
in perf_event::drain_irq_samples.
ROOT (observer effect): the stall-watchdog ITSELF enables perf (trap.rs:272,
set_enabled(true) for its `syscalls` forward-progress counter, never balanced) ->
perf::enabled()=true forever -> drain_irq_samples (gated on that bool) scans
MAX_CPUS*depth on EVERY syscall -> monopolizes cpu0 -> the stall the watchdog
"detects." Confirmed via a new dump line: `perf: active_events=0 enabled=true`
(refcount 0 but bool leaked true).
FIX (committed cabedc8c): drain_irq_samples / on_task_switch gate on the
ACTIVE_PERF_EVENTS refcount (source of truth for "are there sample events"), NOT
the desync-prone enabled() bool. Rewrote the drain-skip test to pin it. Production
unaffected (the watchdog isn't compiled there; enabled tracks the count).
RESULT: with the perf fix + BACKSTOP REMOVED, syscall_abi 1102 pass/0 fail +
boot-smoke CLEAN EXIT — NO stall. The perf-drain monopolization WAS the reliable
blocker. (A per-CPU LAPIC periodic tick at the preempt vector already exists
(apic.rs on_timer_tick, self-rearming, wheel-independent) and preempts fine once
the drain isn't hogging the CPU IF=0.)
CAVEAT: one earlier backstop-removed boot stalled in narf_graphics::console::
scroll_up_one_row (FB console scroll) — intermittent, partly the watchdog's own
verbose output driving heavy scroll. Re-running to gauge reliability. Added
per-CPU tick + try_preempt bail counters to the dump (ticks=/preempt(en/usr/
notask/nopre/slice/done)=) to diagnose any recurrence.
