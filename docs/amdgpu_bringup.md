# amdgpu bring-up: remaining work

Status as of 2026-10-29, based on `main` at `8da5a8b52` (#1207), plus the
VDDNB/input-power additions described below. Evidence below the "Verified on
hardware" section comes from code review and software tests, including QEMU
and register/fake-engine models.

## Verified on hardware (RX 6750 XT, Navi22, VFIO bench)

- PSP/SOS, SMC, GFX/SDMA firmware load and the kernel queue ring/IB tests.
- Native DCN3.0 HDMI modeset to a CachyOS login screen.
- DIRTYFB damage tracking: partial copies of only the damaged rows.
- JPEG 3.0 ring test.

## Waiting on the next bench run

Rebuild from the checkout being validated and run
`sudo ./target/host-narf/vfio-host-20261025/run-gpu-bench-root.sh`, then
`ssh -p 22222 <user>@127.0.0.1` into the guest.

1. **VCN under DPG** (`5a46a09cb`). `dmesg | grep -i -E 'amdgpu: (navi22|VCN)'`
   should show VCN0's decode ring test passing, then the encode and IB
   tests. On failure, the `amdgpu: VCN0 decode ring never ran (Dpg)`
   line gives the register values. `amdgpu.rdna2_vcn_dpg=0` brings back
   the old static path for comparison.
2. **Mesa 3D.**
   - `EGL_PLATFORM=surfaceless eglinfo -B` should name
     `AMD Radeon RX 6750 XT (radeonsi, navi22, ACO, DRM 3.64…)`, not
     llvmpipe.
   - `RADV_DEBUG=startup vulkaninfo --summary` should list `RADV NAVI22`.
   - Then `vkcube --c 300`, and `DISPLAY=:0 glxgears -info` once a
     desktop is up.
3. **Video.** Once VCN passes: `vainfo --display drm --device
   /dev/dri/renderD128` and `/mesa-amd-video.sh` (prints `VIDEO-OK`).
4. **Statistics.** Exercise INFO queries through both primary and render
   nodes at idle and under a rendering workload. Check advancing timestamps,
   fresh clocks/load/temperature/power/voltage, stable/peak P-states and
   memory movement/eviction counts. Repeat on RX 9000 when hardware is
   available; the Navi48/Navi44 coverage below is software-only.

## Bare-metal boot

There are already bootloader entries (`/boot/narf-frame-grub`,
`/boot/narf-kernel-0.5.0`). Before the first attempt:

- **Never let it write to the CachyOS root.** CachyOS is on the WD SN770,
  and Linux's nvme names can swap between boots. The entry's command line
  must say `narf.disks=root-ro` or `boot-only`, never `root-rw`.
- **Keep a boot log.** Insert the `NARFBOOT` stick and keep
  `narf.bootlog=<token>` on the command line. The desktop has no serial
  console.
- **Rebuild the entry from `main`** so it includes the DPG change. The
  `grub-image --root-policy root-ro` command is in
  [BOOTING_ON_CACHYOS.md](BOOTING_ON_CACHYOS.md#booting-the-installed-root-narfdisksroot-ro--root-rw).
- **Use wired networking** for SSH: the I225-V and its `igc` driver,
  which is built by default. The MT7922 Wi-Fi driver has only been
  tested against models.

Not covered by the VFIO bench: the host's own ACPI, interrupt routing,
IOMMU and timers; xHCI keyboard input; NVMe on the real controller.

## Remaining amdgpu work, in priority order

1. **Remaining Mesa ABI gaps** (see
   `drivers/gpu/research/navi22-mesa-abi.md` §12):
   - Fence errors after a GPU reset aren't reported through `WAIT_CS` or
     `WAIT_FENCES`.
   - GDS/GWS/OA allocations are missing.
   - Native RX 6000 scanout supports linear modifiers only; tiled scanout
     needs a separate implementation and hardware validation.
2. **GFXOFF.** Mark the command-submission path's GC MMIO GFXOFF-safe,
   so the graphics block can power down when idle. Until then the power
   policy refuses GFXOFF.
3. **VCN power.** No idle work exists, so an instance stays DPG-paused
   after its first encode use, and stop doesn't send `PowerDownVcn`.
   Linux unpauses and gates an idle instance.
4. **Multi-display.** Presentation on secondary CRTCs is still opt-in
   (`amdgpu.rdna2_multi`).
5. **GDDR6 short-training resume.** Needed for S3 and runtime resume.
   Boots that trained memory can't recover today.
6. **DisplayPort on hardware.** Needs a DP monitor; test with
   `NARF_BENCH_CMDLINE="amdgpu.rdna2_connector=dp"`.
7. **Reset behaviour.** User CPU mappings of VRAM aren't revoked during a
   reset, matching Linux. Decide whether to keep that.
8. **RX 9000 (Navi48, DCN 4.0.1).** Every Navi22 display fix has been
   ported, but only model tests cover them; there's no card. Port each
   later Navi22 fix too.
9. **Documentation.** The `STATUS.md` "Open" list for RX 6000 still says
   "any boot on RX 6000 silicon". The VFIO bench has done that, so update
   it once the next run's results are in.

## Implemented since the older Mesa gap list

- **Statistics on RX 6000 and RX 9000.** Native primary/render nodes answer
  TIMESTAMP and the supported Linux SENSOR selectors, including all four
  stable/peak GFX/MCLK queries. Measurements use fresh SMU telemetry; P-states
  use actual DPM endpoints and Linux's per-ASIC/board standard-clock rules.
  RX 9000 queries resume the GPU before taking the owner. VDDNB now exposes
  live VDD_SOC on both families (SMU11 VID, SMU14 average voltage).
  GPU_INPUT_POWER returns the latest firmware-averaged socket-power sample,
  which can equal GPU_AVG_POWER; a separate instantaneous measurement is
  unavailable. Both are also exposed through hwmon in1_input (vddsoc) and
  power1_input. Missing/invalid measurements return EINVAL through INFO.
  DPM unavailable returns ENOENT; loss/revocation never returns stale
  successful data. These paths still need physical Mesa validation.
- **Memory counters on both families.** NUM_BYTES_MOVED and NUM_EVICTIONS
  count committed GEM moves and successful pressure/suspend evictions per
  card. NUM_VRAM_CPU_PAGE_FAULTS is zero because invisible VRAM cannot be
  CPU-mapped and there is no fault-driven TTM migration path. The u32
  VRAM_LOST_COUNTER reports completed full native recoveries. Counters
  survive heap re-registration; failed or no-op moves do not increase them.
- **Memory queries.** MEMORY and VRAM_GTT report the real
  GEM GTT capacity instead of zero. Live queries use the open's registered
  client VRAM heap for usable sizes and usage instead of assuming all VRAM
  except 8 MiB is allocatable. VRAM_USAGE, VIS_VRAM_USAGE and GTT_USAGE return
  live byte counts. GTT capacity and usage follow GEM's shared system-memory
  budget. These changes still need Mesa validation on the VFIO bench.
- **Already in `main`.** Per-client VMID/PASID management and GPUVM_FAULT,
  GEM_USERPTR, PRT/sparse mappings, SET_PLACEMENT, linear KMS modifier
  advertisement, and device-info clock/VRAM/PCIe/MALL fields have code and
  model coverage. Their presence does not establish hardware acceptance.

Validation for the statistics and memory changes: native ioctl, MMIO and SMU
model regressions cover both families. `cargo xtask test --subsystem drivers/gpu`
reports 2,652 pass / 0 fail / 5 skip with `--arch x86_64`, and 2,106 pass /
0 fail / 1 skip with `--arch aarch64`. Regressions cover native VID and
SOC-voltage decoding, sensor/hwmon units, missing values, short replies,
refresh errors/cancellation and split timestamp register/loss handling.
GPU Clippy passes in all three feature contexts on both architectures;
`cargo fmt --all -- --check` passes. Production boot-smoke and btrfs
interoperability checks also pass on both architectures.

## Not amdgpu, but seen during bring-up

- Intel display: the `DDI_AUX_CTL` sync-pulse fields and the
  `read_full_edid` segment pointer.
- MT7922 Wi-Fi: no hardware acceptance yet.
