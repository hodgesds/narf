# Mesa radeonsi + RADV on NARF

Userspace half of milestone 9 of the RX 6750 XT (Navi22) bring-up: a
reproducible Mesa 26.2.4 build with the AMD hardware drivers, staged into a
NARF rootfs next to the existing software fallback, a smoke that runs inside
NARF under QEMU, and the checklist for the first bare-metal run. The kernel
side (GEM/VA/CS, the AMDGPU_INFO answers) is milestone 8/9 kernel work; the
ABI it has to satisfy is audited in
[`drivers/gpu/research/navi22-mesa-abi.md`](../drivers/gpu/research/navi22-mesa-abi.md).

## What NARF already ran, and what this adds

NARF does not port Mesa. It runs distro Mesa unmodified on its
Linux-compatible syscall surface: the GL image (`REGEN_gl_rootfs.sh`) and the
Alpine KDE image install Alpine edge's musl Mesa packages, the Fedora image
installs Fedora's glibc Mesa, and the desktop launchers force llvmpipe
(`LIBGL_ALWAYS_SOFTWARE=1`) because no QEMU card has a hardware Mesa driver
behind it. libdrm is vendored the same way: `REGEN_modetest.sh` builds the
pristine libdrm 2.4.134 tarball into the checked-in `modetest_x86_64`.

This adds a from-source build that keeps both conventions:

| Piece | File |
|-------|------|
| Build recipe | `verification/data/musl-demo/REGEN_mesa_amd.sh` |
| Image staging + smoke script | `verification/data/musl-demo/REGEN_amd_gl_rootfs.sh` |
| Probe (libs / drm / vk / egl) | `verification/data/musl-demo/mesa_amd_probe.c` |
| ioctl recorder (LD_PRELOAD) | `verification/data/musl-demo/narf_ioctl_trace.c` |
| Fedora launcher driver choice | `verification/data/musl-demo/fedora-systemd-start.sh` |

Nothing these scripts produce is committed; outputs land in `target/`.

## Build recipe

```sh
sh verification/data/musl-demo/REGEN_mesa_amd.sh
```

- **Sources:** the Mesa 26.2.4 and libdrm 2.4.134 release tarballs, pinned by
  sha256 in the script (Mesa's matches the sha512 in Alpine's APKBUILD for
  the same release). They are extracted only inside the build root
  (`MESA_AMD_WORK`, default `target/mesa-amd-work`).
- **Toolchain / libc:** an Alpine edge build root populated by `apk.static
  --usermode` and entered with `unshare --user --map-root-user` + `chroot`
  — unprivileged, no host compiler involved. Alpine edge is what every NARF
  musl image already runs, and it ships the same Mesa 26.2.4 and libdrm
  2.4.134, so the result is ABI- and layout-compatible with the packages it
  replaces (`/usr/lib/libgallium-26.2.4.so`, `/usr/lib/dri`, ICD JSON in
  `/usr/share/vulkan/icd.d`). Every build-root package version is recorded.
- **libdrm 2.4.134** is built first (amdgpu, radeon, intel, nouveau, vmwgfx;
  test programs installed — `amdgpu_stress`, `modetest`, `drmdevice`) and
  Mesa links against exactly that `libdrm_amdgpu` (Mesa 26.2 requires
  ≥ 2.4.133). `amdgpu.ids` provides the marketing name (`73DF:C0` → "AMD
  Radeon RX 6750 XT").
- **Mesa options** mirror Alpine's APKBUILD (prefix, `-O2 -g1`,
  `b_ndebug`, x11+wayland platforms, GLX dri, GBM, shared LLVM,
  `amdgpu-virtio`) with this driver set:
  - `gallium-drivers=radeonsi,llvmpipe,softpipe,virgl`
  - `vulkan-drivers=amd,swrast`, `vulkan-layers=device-select`
  - `amd-use-llvm=false` — radeonsi and RADV compile every shader with
    **ACO**. Mesa 26.2 does not need LLVM for either AMD driver;
    `libvulkan_radeon.so` has no `libLLVM` dependency at all.
  - LLVM (Alpine `llvm23`, shared) is still linked into `libgallium` because
    **llvmpipe** — the software fallback — and lavapipe need it. Dropping
    llvmpipe would make LLVM optional, but would also remove the fallback
    every QEMU desktop currently runs on.
  - `virgl` keeps `REGEN_gl_rootfs.sh`-style QEMU virgl rendering working
    when this build replaces Alpine's; `amdgpu-virtio` lets radeonsi/RADV run
    over a virtio-gpu DRM native context (`XTASK_GPU_DRM_NATIVE=1`) where the
    host supports it.
  - `gallium-va=enabled`, `video-codecs=all` (as Alpine): radeonsi's VA-API
    driver (`/usr/lib/dri/radeonsi_drv_video.so`, against Alpine's libva)
    and RADV's Vulkan video (`VK_KHR_video_decode/encode_*`) over the VCN
    3.0 decode/encode and JPEG 3.0 rings the kernel exposes while
    `accel` is on (the default; `amdgpu_vcn_navi22_cs`).
  - Not built: rusticl, zink, VDPAU, other vendors' drivers.
- **Also built:** `mesa_amd_probe` and `narf_ioctl_trace.so`, against the
  just-installed libraries.

A build directory configured with different meson options (for example one
made before VA-API was enabled) is discarded and configured again; an older
build root gets `libva-dev` added.

Outputs (`target/narf-mesa-amd/`): the install tree as
`narf-mesa-amd-26.2.4-x86_64.tar.gz`, `MANIFEST.sha256` (per-file), and
`BUILDINFO` (source hashes, meson options, build-root package list). A full
build is ~10 minutes at `-j6`; reruns are incremental (`MESA_AMD_REBUILD=1`
starts clean).

## Staging into the image

```sh
sh verification/data/musl-demo/REGEN_amd_gl_rootfs.sh
```

builds `target/narf-amd-gl-vblk.img` (ext2, mounted by NARF at `/mnt`):

1. Alpine edge base + Alpine's own `mesa-*` packages, installed **only** to
   pull in the exact runtime closure of a Mesa 26.2.4 build (llvm23-libs,
   libelf, libxcb, wayland, libdisplay-info, eudev-libs, …), plus the
   on-hardware test clients: `mesa-demos` (eglinfo/glxinfo),
   `vulkan-tools` (vulkaninfo/vkcube), `kmscube`, weston with the DRM
   backend and `weston-simple-egl`, `strace`, and for video `libva`,
   `libva-utils` (vainfo) and `ffmpeg` (VA-API and Vulkan hwaccels).
2. Every file Alpine's mesa packages installed is deleted, then the
   from-source tree is extracted over `/` (runtime files only). A missing
   radeonsi/RADV/lavapipe/libdrm_amdgpu file aborts the build.
3. `/mesa-amd-smoke.sh` (also `/probe.sh`, `chroot_run`'s default payload),
   and `/mesa-amd-video.sh`, the on-hardware video check.
4. `/video`: reference clips made with the image's own ffmpeg at build time
   (30 frames of `testsrc2` 1280×720: H.264 High via libx264, HEVC Main via
   libx265, AV1 via libaom/libsvtav1 when present, one baseline JPEG) and
   each one's software-decode NV12 MD5 (`-vf format=nv12 -f md5`). The
   generation runs in a user-namespace chroot of the image;
   `MESA_AMD_NO_CLIPS=1` skips it.

**Driver selection** needs no configuration. Mesa's loader maps the kernel
driver name from `DRM_IOCTL_VERSION` to a gallium driver: `amdgpu` →
radeonsi, `virtio_gpu` → virgl, anything else with KMS → kms_swrast
(llvmpipe). RADV only claims render nodes whose kernel driver is amdgpu.
Failure is already handled by Mesa:

- GBM (`gbm_create_device`, the compositor path) retries
  `dri_screen_create_sw` when the hardware screen fails;
- `eglInitialize` retries in software when the hardware driver fails;
- RADV skips the node (`RADV_DEBUG=startup` says why) and the Vulkan loader
  falls through to lavapipe if its ICD is visible.

`LIBGL_ALWAYS_SOFTWARE=1` alone does **not** move a GBM-backed compositor to
llvmpipe — GBM picks its driver before EGL reads that variable. Set
`GBM_ALWAYS_SOFTWARE=1` as well when the CPU renderer must be guaranteed.

The Fedora launcher (`fedora-systemd-start.sh`) still forces llvmpipe on
every QEMU card, but no longer does so when an amdgpu render node exists
(its `uevent` says `DRIVER=amdgpu`), so Fedora's own radeonsi is used on the
RX 6750 XT. `NARF_MESA_SOFTWARE=1` restores the unconditional fallback.

## Smoke under QEMU

```sh
NARF_VBLK_IMG=target/narf-amd-gl-vblk.img XTASK_RI_ECHO_TIMEOUT_SECS=600 \
    cargo xtask run-interactive \
    --cmd "chroot_run /bin/busybox sh /mesa-amd-smoke.sh" --expect "MESA-AMD-OK"
```

(`--gpu-backend virgl --display egl-headless` adds a virtio-gpu render node;
the smoke passes on either backend.) Steps, each a separate process with its
exit status checked (a signal always fails the run):

| Step | Proves | Pass condition with no AMD GPU |
|------|--------|--------------------------------|
| `libs` | libgallium (radeonsi + `amdgpu_winsys_create`) and `libvulkan_radeon.so` load with `RTLD_NOW` and export their entry points | rc 0 |
| `drm` | every `/dev/dri` node enumerates through libdrm; `amdgpu_device_initialize` from libdrm_amdgpu runs against each | rc 0, `amdgpu_nodes=0`, each node a clean error |
| `vk-radv` | Vulkan loader + RADV ICD alone | instance created, 0 devices |
| `vk-lavapipe` | Vulkan software fallback | ≥ 1 device |
| `egl-default` | EGL device + GBM platforms with the loader's own choice, plus a GLES2 triangle with pixel readback | rc 0, correct pixels |
| `egl-radeonsi` | radeonsi forced on every node (`MESA_LOADER_DRIVER_OVERRIDE`) | rc 0, no `class=amd`, falls back |
| `egl-swrast` | the llvmpipe fallback the desktops use | every renderer llvmpipe |
| `va` | radeonsi's VA driver through libva-drm on every render node (`LIBVA_DRIVER_NAME=radeonsi`), plus `mesa_amd_probe libs` resolving `__vaDriverInit_1_*` | rc 0, `amd_va=0`, each node a VA error status |
| `vainfo` | the libva-utils client the on-hardware list starts with | any rc, no signal |
| `ffmpeg-vaapi` | ffmpeg's VA hwaccel on `/video/h264.mkv` | any rc, no signal |

`IOCTL …` lines interleaved in the output come from `narf_ioctl_trace.so`
(LD_PRELOAD on the `drm`, `vk-radv`, `egl-*` and `va` steps). A step
"crashes" only on a signal exit (129–192); ffmpeg's negative AVERROR exits
(251–255) are ordinary errors: one line per DRM
ioctl with the AMDGPU_INFO query decoded and the kernel's answer.
`MESA_AMD_HOST_CHECK=1 sh REGEN_amd_gl_rootfs.sh` runs the same script in a
user-namespace chroot on the build host; on a Linux host with an amdgpu GPU
that yields the Linux reference trace for the same binaries
(`target/narf-mesa-amd/host-check.log`).

## Results so far (2026-10-17)

**NARF under QEMU** (default backend: virtio-gpu 2D `card0`/`renderD128` +
the in-tree `narf-drm` bochs card `card1`/`renderD129`, no AMD GPU):
`MESA-AMD-OK`. Every step exited 0; no signal. libgallium/RADV load,
`amdgpu_device_initialize` declines all four nodes (render nodes: "DRM
version is 0.1.0/1.0.0 but this driver is only compatible with 3.x.x",
`-EBADF`; primary nodes: `amdgpu_get_auth` fails, see below), RADV creates an
instance and finds 0 devices, lavapipe finds 1, and every EGL/GBM session
renders the triangle correctly on llvmpipe (radeonsi forced: EGL device
init fails cleanly, GBM falls back to kms_swrast). The kernel's
`ld-musl` must be staged for `chroot_run` to exec — on a host without a musl
package, point `LDMUSL_PATH` at the build root's
`/lib/ld-musl-x86_64.so.1`.

**Video under QEMU** (2026-10-17, VA-API + Vulkan video build, same
backend): `MESA-AMD-OK`. `libs` resolves `__vaDriverInit_1_24` in
`radeonsi_drv_video.so` (libva 2.24); `va` gets `vaInitialize` = 2
("resource allocation failed") on both render nodes, `amd_va=0`; `vainfo`
exits 3 and `ffmpeg -hwaccel vaapi` on `/video/h264.mkv` exits 251
(AVERROR(EIO), "Device creation failed: -5") — clean errors, no signal.
The image build generated all four reference clips (H.264, HEVC, AV1 via
Alpine's ffmpeg, JPEG) and their MD5s.

**Same binaries on a Linux host** (`MESA_AMD_HOST_CHECK=1`, amdgpu 3.64,
Raphael iGPU GC 10.3.6 — not Navi22): `MESA-AMD-HW=amd`. radeonsi
(`radeonsi, raphael_mendocino, ACO, DRM 3.64`) renders the triangle through
both EGL device and GBM; RADV enumerates `RADV RAPHAEL_MENDOCINO`. This
validates the build itself on real AMD silicon and provides the reference
ioctl sequence below.

### ioctls Mesa issued

Under NARF (no amdgpu), the complete set across all steps:

| ioctl | Node | NARF answer | Note |
|-------|------|-------------|------|
| `VERSION` (×2 per open) | all | ok: `virtio_gpu` 0.1.0, `narf-drm` 1.0.0 | loader driver choice |
| `GET_CLIENT` | primary (`card*`) | **`-ENOTTY`** | libdrm `amdgpu_get_auth()` issues it on every primary node before anything else; Linux answers it. On the RX 6750 XT this makes `amdgpu_device_initialize` fail for any client that opens `card0` (GBM/kmscube/compositors) — **gap for the uapi workstream** |
| `GET_CAP(PRIME)` | all | 3 | |
| `VIRTGPU_GETPARAM` 1–7 | virtio | ok | virgl probe |
| `VIRTGPU_GET_CAPS` capset 6 (DRM native ctx) | virtio | `-ENOSYS` | RADV/radeonsi `amdgpu-virtio` probe; matches Linux with no capsets |

Linux reference, RADV and radeonsi device init on GFX10.3 (identical order
for both drivers up to `MAX_IBS`; render node unless noted):

1. `VERSION` ×2 (+ `GET_CLIENT` first on a primary node)
2. `AMDGPU_INFO`: `ACCEL_WORKING` → `DEV_INFO` (size 448) →
   `READ_MMR_REG 0x263e` count 1 instance 0xffffffff →
   `HW_IP_COUNT(GFX)` → `HW_IP_INFO(GFX)` (size 32)
3. `GET_CAP(SYNCOBJ_TIMELINE)`; radeonsi then `SYNCOBJ_CREATE` (winsys VM
   timeline syncobj)
4. `DEV_INFO`, `READ_MMR_REG 0x263e`, `DEV_INFO` again (ac_gpu_info)
5. `HW_IP_INFO` + `HW_IP_COUNT` for GFX, COMPUTE, DMA, UVD, VCE, UVD_ENC,
   VCN_DEC, VCN_ENC, VCN_JPEG, VPE — absent IPs: `HW_IP_INFO` succeeds with
   zeros, `HW_IP_COUNT` returns `-EINVAL`
6. `FW_VERSION` GFX_ME, GFX_MEC, GFX_PFP (index 0), VCN
7. `MEMORY` (size 96), `GET_CAP(ADDFB2_MODIFIERS)`, `VIDEO_CAPS` decode and
   encode (size 192), `MAX_IBS` (size 40)
8. radeonsi: `GET_CAP(PRIME)`, `CTX` alloc (priority 0), then BOs:
   `GEM_CREATE` (4 KiB / 2 MiB, domains GTT `0x2` or VRAM|GTT `0x6`, flags
   `CPU_ACCESS_REQUIRED`/`NO_CPU_ACCESS`-class `0x4`/`0x6`), `GEM_MMAP`,
   `GEM_VA MAP` at `0xffff8001_00000000`+ (high VA, flags `0xe`/`0x8e`);
   first draw: `SYNCOBJ_CREATE`, `CS` with chunks BO_HANDLES(6),
   SYNCOBJ_TIMELINE_SIGNAL(9), FENCE(2), IB(1), `SYNCOBJ_WAIT`; teardown
   `GEM_VA UNMAP` + `GEM_CLOSE` per BO, `CTX` free, `SYNCOBJ_DESTROY`.
9. RADV: `SYNCOBJ_CREATE/WAIT/DESTROY` probe, `CTX` alloc at priorities
   low/normal (high/realtime get `-EACCES` unprivileged — expected).

## Bare-metal checklist (RX 6750 XT)

Prerequisites from the kernel side, in the order Mesa trips over them
(`navi22-mesa-abi.md` §1): the amdgpu card answers `DRM_IOCTL_VERSION` as
`amdgpu` 3.x with minor ≥ 54, `ACCEL_WORKING` = 1, `DEV_INFO` with the right
`external_rev` and CU bitmap, `READ_MMR_REG(0x263e)`, GFX/compute
`available_rings` ≠ 0, `FW_VERSION` ME/MEC/PFP, `MEMORY`, binary syncobjs on
the amdgpu node, then GEM/VA/CS for the first submission. Until then every
step below must still exit cleanly and fall back to llvmpipe.

Run from the image (`chroot_run /bin/busybox sh …`), capturing serial:

1. `/mesa-amd-smoke.sh` — expect `MESA-AMD-OK` and `MESA-AMD-HW=amd`.
   `MESA-AMD-HW=fallback` means the drivers declined the node: the `IOCTL`
   lines show the first query that failed.
2. `mesa_amd_probe drm` — `marketing="AMD Radeon RX 6750 XT"`,
   `asic=0x73df`, `ext_rev=0x32`+, `family=143`, GFX `discovery=0x0a0302`.
3. `eglinfo -B` (`EGL_PLATFORM=surfaceless` and `gbm`) — renderer
   `AMD Radeon RX 6750 XT (radeonsi, navi22, ACO, DRM 3.x, …)`; never
   llvmpipe.
4. `RADV_DEBUG=startup vulkaninfo --summary` — one `RADV NAVI22` device,
   `driverID = DRIVER_ID_MESA_RADV`, plus lavapipe.
5. Triangle: `mesa_amd_probe egl` (GLES2 FBO triangle + readback, `tri … ok`
   on the AMD renderer); then `kmscube --count=300` on `/dev/dri/card0`
   (GBM + EGL + KMS page-flips of GPU-rendered buffers, the compositor
   pattern without a compositor).
6. Vulkan draw: `vkcube --c 300` (headless, `VK_KHR_display` or
   `--wsi display` when available) — exercises RADV CS, syncobjs, WSI.
7. Compositor: `weston --backend=drm --renderer=gl` on the native KMS card,
   then `weston-simple-egl` inside it — client rendering through radeonsi,
   dma-buf sharing, compositor composition, scanout. Then the Fedora Plasma
   image (`fedora-systemd-start.sh` now leaves radeonsi enabled).
8. Repeat 3–5 with `LD_PRELOAD=/usr/lib/narf/narf_ioctl_trace.so` and diff
   against the Linux reference trace for the same Mesa build.

9. Video (needs `accel`, on unless `amdgpu.rdna2_accel=0`; the boot log shows
   `amdgpu: navi22 media rings for clients 0xf`): `LIBVA_DRIVER_NAME=radeonsi
   mesa_amd_probe va` — one node with `vendor="Mesa Gallium driver … for AMD
   Radeon RX 6750 XT"` and H264High/HEVCMain/HEVCMain10/VP9Profile0/
   AV1Profile0/JPEGBaseline decode plus H264/HEVC encode; `vainfo --display
   drm --device /dev/dri/renderD128`; `RADV_DEBUG=startup mesa_amd_probe
   vk` — `VK_KHR_video_decode_h264/h265/av1=1` and a queue with
   `video_decode=1`. Then `/mesa-amd-video.sh` (prints `VIDEO-OK`): VA-API
   and Vulkan decode of `/video/{h264,hevc,av1}.mkv` and VA-API JPEG decode
   must match the software-decode MD5 bit for bit, and VA-API H.264/HEVC
   encode of 60 frames must decode back to 60 frames. On a mismatch rerun
   the failing ffmpeg line with `LD_PRELOAD=/usr/lib/narf/narf_ioctl_trace.so`
   and `AMD_DEBUG=` / `RADV_DEBUG=` to see the CS that ran.

Failure handling to verify on hardware: kill a client mid-submission
(context teardown), `AMD_DEBUG=` off/`RADV_DEBUG=hang` on a hang, and that a
rejected CS returns an error to Mesa rather than wedging the ring.

## RX 6000 boot options

Every functionally complete RX 6000 feature is on by default. Firmware,
kernel queue proofs and native modeset programming have executed on the
RX 6750 XT; a visible native Plasma session remains unverified. Each feature
has an off switch for bring-up:

| Feature | Default | Off / on |
| --- | --- | --- |
| Native HDMI/DP display (retires the GOP) | on | `amdgpu.native_display=0` |
| Native client submission (radeonsi/RADV, VCN/JPEG) | on | `amdgpu.rdna2_accel=0` |
| DCN3.0 hardware cursor | on | `amdgpu.rdna2_hw_cursor=0` |
| Power saving (GFXOFF, CG, hub PG, memory/fabric DPM, deep sleep, PMFW watermarks) | all requested | `amdgpu.rdna2_pg=none`, or a list such as `amdgpu.rdna2_pg=gfxoff,cg` |
| Automatic GPU recovery after a hang (mode1, at most 3 per boot) | on | `amdgpu.gpu_recovery=0` |
| Multi-display (secondary CRTCs) | off | `amdgpu.rdna2_multi` |

Multi-display stays opt-in because secondary CRTCs light with static
scanouts: they cannot present or deliver vblank yet. Each requested power
feature is still refused unless its display admission (DML p-state/stutter
support, watermarks, clock floors) and driver prerequisites hold; the boot log
names every refusal. If native modeset fails after the GOP stream is retired
the screen stays dark: reboot with `amdgpu.native_display=0`. A detected ring
hang (2 s without fence progress) mode1-resets and re-initializes the card,
as Linux's `amdgpu.gpu_recovery` does; contexts see VRAM lost and in-flight
work fails. A boot that needed GDDR6 training cannot recover yet, and after
three recoveries the card is left stopped, because each recovery leaks the
old owners' quarantined VRAM. A hang that keeps returning needs a reboot with
the suspect feature off.

At runtime, `/sys/class/drm/card<N>/device/power_dpm_force_performance_level`
accepts `auto`, `low` and `high` (GFXCLK only; memory clocks stay with the
display), and `pp_features` shows Linux's PMFW feature table and accepts a hex
mask that may toggle GFXOFF, hub power gating, memory/fabric DPM and deep
sleep. Enabling still passes the display-admission gates, and other bits are
read-only.

Switches take a bare flag or `=1|on` and `=0|off`; other values keep the
default. The old `amdgpu.navi22_*` spellings remain supported and the
canonical name wins. An explicit `rdna2_pg` value takes precedence over
`navi22_pg`, including an empty or invalid value; invalid lists enable
nothing.

## RX 6000 software behavior

### Entry-path audit, 2026-10-23

The follow-up [DCN3.0 HDMI audit](NAVI22_HDMI_AUDIT.md) records the selected
Linux callbacks, missing VTG and progressive-timing initialization, explicit
DIO routing, and the single-stream MPC output-rate gap. It distinguishes
register-model evidence from physical sink lock and visible output.

The CachyOS audit follows `fb/src/amdgpu_boot.rs` through the retained RDNA2
platform, display monitor and first DRM client operations. Linux references
are the local checkout at `ecd997b0189a`; register fields were compared with
both DCN 3.0.0 and 3.1.4 headers where the owners are shared. Kernel register
models establish sequencing and lifetime behavior; they do not establish a
physical HDMI link or Mesa shader execution on this card.

| Entry / continuation | Native evidence and audit outcome |
| --- | --- |
| Preflight, firmware, GMC/GART, doorbells, kernel GFX/compute/SDMA queues | Latest boot completed these stages and their ring/IB proofs. Reviewed readiness gates before client publication; user VMIDs and context switching have separate submission models. |
| IH delivery, faults, HPD and display interrupts | Native IH proof used polling. Source routing, subscribe-before-enable, acknowledgement and bounded polling fallback are covered by existing models. Physical MSI delivery is unverified. |
| DMUB, connector detection, HDMI clocks/attributes/SCDC | DMUB started and the Lenovo sink was detected. Compared the timing/PHY/SCDC sequence with Linux. Moved `max_bpc` application before the first modeset. The saved SCDC sample precedes final unblank; it does not establish settled link lock. |
| HUBP/DPP/MPC activation | Fixed inherited rotation, alignment, alpha/metadata, VMID/stereo state; initialized conversion, color/scaler bypass and line-buffer storage; bypassed an inherited output-gamma LUT. The continuation audit also adds Linux's HUBP power-up ECO/TTU initialization and device-derived fabric geometry. Power brackets preserve inherited requests and release their own request on errors/cancellation. Poisoned-state regressions fail the original code. |
| Native KMS publication and first client commit | Fixed inherited RDNA4 overlay/modifier capabilities. DCN30 now advertises LINEAR 8888 explicitly, accepts matching GEM framebuffers, resolves atomic placement targets, and retains their pins into presentation. Tests cover publication, ADDFB2, TEST_ONLY, rejection and handoff. |
| Render completion, copying, page flip and vblank | Fixed missing GEM-source presentation. Retained placements wait on rendering outside OWNER; visible VRAM copies rows and hidden VRAM uses SDMA readback. Tests cover offsets, bounds, format rejection, pins and fence/owner ordering. Existing flip models cover latch, timeout, address order and wrapped frame counts. |
| Cursor and hotplug / later modeset | Reviewed the existing cursor placement/locking, EDID re-probe and KMS convergence paths and their models. Secondary CRTCs still have no presentation/vblank implementation and remain opt-in. |
| Post-modeset power saving | Latest boot failed on an all-ones RLC override read after partial writes. Its full-word override operand now follows Linux's RMW, with a fresh running-RLC control probe before accepting all-set data; status and other control reads still fail on all ones. Native RX 6000 submission now declares GC access guarded: submission, READ_MMR_REG, TDR and kernel VRAM work acquire a GFXOFF reference and recheck activation/reset epoch under the owner. Other policy prerequisites still apply. Physical power transitions remain unverified. |
| Recovery, cancellation and device loss | Native RX 6000 tracks guilty hangs, cancelled pending jobs and device loss separately from physical retirement. Shared WAIT_CS and WAIT_FENCES all/any keep the original job/submitter across reset on RX 6000 and RX 9000. Failed jobs wake waiters without releasing unconfirmed memory. Physical mode1 reset remains unverified. |
| VCN idle and resume | RX 6000 VCN3 idle work releases encode DPG pause after physical completion, stops idle instances after one second and conditionally sends SMU PowerDownVcn. Begin-use restores power/hardware while preserving sessions and logical fences; JPEG remains independent. MM_DPM_PG keeps its existing opt-in. Static/DPG, cancellation and failure paths have model coverage; physical acceptance remains pending. |
| Optional media and topology | Native VCN degraded to `BootFailed(0)` and topology returned `Readback`; JPEG verified. Topology now checks defined GRBM selector fields while ignoring reserved read bits; a stuck real selector still fails. Native topology and VCN decoding remain unverified. |

The earlier native boot also failed in the dynamic loader before Plasma
startup. The separate VFS/Btrfs fixes and their private-mmap regression must
be included in the same production image. Complete software checks and
package/boot-chain verification precede another hardware attempt; add live
tracing only where the code audit and models leave a specific question.

The 2026-10-26 VFIO run exposed an additional launcher defect: QEMU's KVM
`host-phys-bits` passthrough overrode `phys-bits=40`. QMP reported 48 effective
bits and the RX 6750 XT VRAM BAR near 14 TiB. The launcher now also supplies
`host-phys-bits-limit=40` (or the caller's explicit width). A disposable KVM
fixture with 12 GiB RAM and a 16 GiB PCI BAR reproduced the old 48-bit/14-TiB
layout; the corrected options report 40 bits and place that BAR at 768 GiB.
This verifies address placement, not visible HDMI. Restart the physical-GPU
VM to apply the corrected layout; a running VM retains its original options.

Device-info replies report VBIOS memory type/bus width and timestamp frequency,
common GPU/slot PCIe capabilities, Linux's per-ASIC Infinity Cache sizes, and
SMU memory-clock limits (boot MCLK while UCLK DPM is disabled). Missing board
metadata stays unknown. Live register queries use Linux's allow-list and wait
for the retained GPU owner with GC powered.

RX 6000 MEMORY/VRAM_GTT replies now expose GEM's actual shared GTT budget
and the open's registered client VRAM heap, including live visible/hidden
VRAM usage. VRAM_USAGE, VIS_VRAM_USAGE and GTT_USAGE return byte counts from
those owners; retained objects still count after their handles close. Snapshot
fallbacks retain the 8 MiB VRAM reservation and now report nonzero GTT capacity.
Native ioctl regressions cover RDNA2 and RDNA4 allocations, release, shared
ownership and bounded copies. Mesa hardware validation remains outstanding.

Both RX 6000 and RX 9000 expose native TIMESTAMP and Linux dGPU SENSOR
statistics on primary/render nodes: effective SCLK, current MCLK, edge
temperature, load, average socket power, VDDGFX, VDDNB and stable/peak GFX/MCLK.
Each query takes the retained owner; RX 9000 resumes runtime PM first.
P-state endpoints come from SMU DPM tables with boot-clock fallback when DPM
is disabled; standard GFX/MCLK follow Linux's ASIC rules on RDNA2 and the
board's Base/Game clocks plus UCLK maximum on RDNA4. VDDNB uses live VDD_SOC
(SMU11 VID decoding; SMU14 average SOC voltage). GPU_INPUT_POWER uses the
latest AverageSocketPower and can equal GPU_AVG_POWER: both are
firmware-averaged, with no distinct instantaneous sensor claimed. These two
selectors extend the Linux dGPU sensor switches. Hwmon adds in1_input with
the vddsoc label and power1_input in microWatts. Missing/invalid readings
remain errors for INFO and empty hwmon values. INFO errors/cancellation
publish no reply.
GEM reports per-card bytes moved and successful evictions after backing
commits, plus the native recovery count as VRAM_LOST_COUNTER. CPU VRAM-fault
migrations remain zero because invisible VRAM mappings are refused. Physical
statistics acceptance remains separate from software-model checks.

Native submissions use FIFO ring admission and IRQ-driven fence/VMID waits.
VM programming has a separate completion writeback before the client IB;
its completion cannot release a VMID whose job is still running. Reset
invalidates old submitters using the fence generation established before
restart.

Ordinary VRAM-preferred allocations can fall back to GTT when VRAM is full,
while retaining their requested preference; discardable VRAM-only allocations
keep stricter placement requirements.
GEM can evict visible-VRAM buffers, including same-card PRIME/shared buffers,
to GTT and promote them back, preserving data. GPU-mapped buffers move under
card admission exclusion after their VMs' jobs and reservation fences settle;
existing PTEs are rewritten and TLB sequences advance before submissions
resume. Strict VRAM allocation retries can reclaim mapped buffers, and CS
applies listed buffers' placement preferences when possible. Cancellation
while waiting leaves mappings unchanged.
Published GEM/PRIME CPU mappings no longer pin placement: a move revokes every
CPU alias in all known address spaces, copies under the freeze, and rebinds
the same virtual addresses and attributes to the new backing (or restores the
old one on failure). Unpublished mappings, deferred CPU user-fence writes,
legacy raw leases and aliases in unknown address spaces (a fork child not yet
visible) still pin backing; device mappings are `VM_SPECIAL`-equivalent and
never become mlocked. Shared handles, exported fds and BO lists retain
identity without pinning placement.
RX6000 invisible VRAM now supports ordered SDMA clearing, eviction to GTT and
NO_CPU_ACCESS promotion back through a reserved BAR staging window. Transfers
retain their allocations across cancellation and replay after recovery; only
real completion permits reuse or user access. Failed copies preserve existing
PTEs and backing. NO_CPU_ACCESS remains enforced for GEM/PRIME CPU mmap even
after moving to GTT.

## Open items

RX 9000 idle-power software now covers independent VCN5/JPEG5 static idle
and resume plus board-supported GC12 GFXOFF. Idle retains codec context,
JPEG copies and fence sequences; normal media traffic uses cached GC
configuration so the graphics island can remain idle. Reset/suspend replace
the GFXOFF controller epoch after fresh native proofs. Use
`amdgpu.rdna4_gfxoff=0` to compare with graphics power gating disabled.
After the native proofs, VCN5 DPG is available on both dies and JPEG5 DPG
on Navi48; Navi44 keeps static JPEG gating. Every DPG restore requires a
new physical fence probe. Board-supported media DPM and DS_VCN follow DPG
activation; recovery returns to static policy for re-proof. Use
`amdgpu.rdna4_media_dpg=0` for static media idle. Physical idle-power, session
retention and reset/resume acceptance on both dies remain pending.

RX 9000 also exposes factory workload presets through
`card<N>/device/pp_power_profile_mode` (0 default, 1 fullscreen 3D, 2 power
saving, 3 video, 4 VR, 5 compute, 7 windowed 3D). The applied preset has `*`;
custom coefficients are unsupported. COMPUTE suppresses only admitted sleep
features, and selection survives reset/resume. Memory/fabric relaxation uses
the existing DML plans with acknowledged watermark/clock admission and strict
runtime floor replies. Board-supported GFX_ULV and DS_DCFCLK have separate
native GC and display-floor admission; `amdgpu.rdna4_gfx_ulv=0` and
`amdgpu.rdna4_dcf_sleep=0` disable them for comparison. These paths remain
software-model tested until acceptance on Navi48 and Navi44.

- The Fedora image runs Fedora's Mesa (glibc), not this build; the musl
  build is the reference that the smoke and ioctl traces describe.
- How the ext2 image reaches the board (USB/NVMe partition vs. the QEMU
  virtio-blk disk) belongs to the bare-metal boot recipe.
- `narf_ioctl_trace.so` sees ioctls made through the PLT only; a raw
  `syscall(SYS_ioctl)` would be missed (Mesa 26.2 / libdrm 2.4.134 make
  none on these paths).
