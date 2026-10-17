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
  - Not built: VA-API, video codecs, rusticl, zink, other vendors' drivers.
- **Also built:** `mesa_amd_probe` and `narf_ioctl_trace.so`, against the
  just-installed libraries.

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
   backend and `weston-simple-egl`, and `strace`.
2. Every file Alpine's mesa packages installed is deleted, then the
   from-source tree is extracted over `/` (runtime files only). A missing
   radeonsi/RADV/lavapipe/libdrm_amdgpu file aborts the build.
3. `/mesa-amd-smoke.sh` (also `/probe.sh`, `chroot_run`'s default payload).

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

`IOCTL …` lines interleaved in the output come from `narf_ioctl_trace.so`
(LD_PRELOAD on the `drm`, `vk-radv` and `egl-*` steps): one line per DRM
ioctl with the AMDGPU_INFO query decoded and the kernel's answer.
`MESA_AMD_HOST_CHECK=1 sh REGEN_amd_gl_rootfs.sh` runs the same script in a
user-namespace chroot on the build host; on a Linux host with an amdgpu GPU
that yields the Linux reference trace for the same binaries
(`target/narf-mesa-amd/host-check.log`).

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

Failure handling to verify on hardware: kill a client mid-submission
(context teardown), `AMD_DEBUG=` off/`RADV_DEBUG=hang` on a hang, and that a
rejected CS returns an error to Mesa rather than wedging the ring.

## Open items

- The Fedora image runs Fedora's Mesa (glibc), not this build; the musl
  build is the reference that the smoke and ioctl traces describe.
- How the ext2 image reaches the board (USB/NVMe partition vs. the QEMU
  virtio-blk disk) belongs to the bare-metal boot recipe.
- `narf_ioctl_trace.so` sees ioctls made through the PLT only; a raw
  `syscall(SYS_ioctl)` would be missed (Mesa 26.2 / libdrm 2.4.134 make
  none on these paths).
