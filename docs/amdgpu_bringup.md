# amdgpu bring-up: remaining work

Status as of 2026-10-29, based on `main` at `eb9c6c8a1` (#1236), plus
RX 9000 idle-power changes on `codex/amdgpu-rdna4-idle-power`.
Evidence below the "Verified on hardware" section comes from code review
and software tests, including QEMU and register/fake-engine models.

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
5. **Recovery and idle power.** Check WAIT_CS and both WAIT_FENCES modes
   on jobs interrupted by recovery, including waits after submitter
   replacement. On RX 6000, check repeated idle/render cycles with GFXOFF
   admitted, and decode/encode workloads separated by more than one second
   of idle. VCN must resume without losing sessions or fence progress;
   JPEG must remain usable. Repeat with `amdgpu.rdna2_vcn_dpg=0` and, when
   opted in, `amdgpu.rdna2_vcn_smu_pg=1` for PMFW power messages.
   On RX 9000, exercise separate and simultaneous VCN5/JPEG5 workloads
   across idle intervals. Sessions, JPEG copy slots and fence progress must
   survive resume. Check graphics-idle power while media runs, then repeated
   render/idle, reset and suspend/resume cycles. Compare against
   `amdgpu.rdna4_gfxoff=0`; repeat on Navi48 and Navi44.

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
   - GDS/GWS/OA allocations are missing.
   - Native RX 6000 scanout supports linear modifiers only; tiled scanout
     needs a separate implementation and hardware validation.
2. **Multi-display.** Presentation on secondary CRTCs is still opt-in
   (`amdgpu.rdna2_multi`).
3. **GDDR6 short-training resume.** Needed for S3 and runtime resume.
   Boots that trained memory can't recover today.
4. **DisplayPort on hardware.** Needs a DP monitor; test with
   `NARF_BENCH_CMDLINE="amdgpu.rdna2_connector=dp"`.
5. **Reset behaviour.** User CPU mappings of VRAM aren't revoked during a
   reset, matching Linux. Decide whether to keep that.
6. **RX 9000 (Navi48, DCN 4.0.1).** Every Navi22 display fix has been
   ported, but only model tests cover them; there's no card. Port each
   later Navi22 fix too.

## Implemented since the older Mesa gap list

- **Fence errors on both families.** WAIT_CS and WAIT_FENCES all/any use
  the job's original submitter across reset/unregistration. Context-local
  history also keeps FENCE_TO_HANDLE and dependencies tied to that job.
  Native RX 6000 now tracks guilty hangs, cancellation and device loss;
  observed completed work keeps success. Errors wake clients without
  freeing resources whose physical completion is unconfirmed.
- **RX 6000 GFXOFF admission.** Submission, register queries, TDR sampling
  and kernel VRAM work hold GC disable references. The owner checks lease
  activation/reset epoch before GC access, closing the enable race. Native
  registration now declares these paths guarded; other policy prerequisites
  still apply. Physical transitions remain unverified.
- **RX 9000 idle power.** VCN5 and JPEG5 independently drain physical work,
  stop and power down after idle; begin-use restores their hardware, IRQs,
  codec context and sequences. The shared media doorbell range stays owned.
  Fence reads use always-on presence while an island is gated. SMU14/RLC
  GFXOFF is board-gated, with GC references around runtime register access
  and fresh controller epochs after reset/suspend. Media traffic alone does
  not keep GC awake. Failed/cancelled transitions stay closed. Physical
  transitions remain unverified. After static native proofs, VCN5 DPG runs
  on both dies; JPEG5 DPG is Navi48-only, while Navi44 keeps static JPEG
  gating. Board-supported MM_DPM and DS_VCN follow successful DPG setup.
  Every SRAM restore needs a new physical fence probe before publication.
  Recovery disables media clock sleep for static re-proof and keeps JPEG
  JMI reset/power-cycle retirement. `amdgpu.rdna4_media_dpg=0` retains
  static media idle and disables this media DPM/deep-sleep transition. Cold media setup now reads GC12's
  segment-relative GB_ADDR_CONFIG at 0x13de; fixtures poison the older offset.
- **RX 6000 VCN3 idle power.** After one second of inactivity and physical
  fence completion, idle work releases encode DPG pause, stops VCN and sends
  PowerDownVcn when MM_DPM_PG is enabled. Begin-use restores power/hardware
  while preserving context and fence sequences; JPEG stays independent.
  Cancelled/failed transitions prevent replay. PMFW media gating keeps its
  existing opt-in.
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

Validation for statistics, memory, recovery and idle changes: native ioctl,
MMIO and SMU model regressions cover both families.
The full GPU suites report 2,710 pass / 0 fail /
5 skip with `--arch x86_64`, and 2,164 pass / 0 fail / 1 skip with
`--arch aarch64`. Coverage includes sensor/hwmon units and missing data,
refresh cancellation, timestamp loss, original fence errors across engine
replacement, GFXOFF activation/cancellation, physical VCN drain and static/DPG
idle/resume failure paths. RX 9000 idle/DPG regressions cover separate PSP
SRAM types, per-die JPEG admission, physical restore probes, retained sessions/IB slots, board feature
masks, full hang recovery, cancellation and failed SRAM uploads.
GPU, framebuffer and USB Clippy pass in all three feature contexts on both architectures;
`cargo fmt --all -- --check` passes. Production boot-smoke and btrfs
interoperability checks also pass on both architectures.

For RX 9000 hardware acceptance, repeat separate and simultaneous VCN/JPEG
workloads with `amdgpu.rdna4_media_dpg=0` and the default policy. Check
repeated idle/use, GC sleeping during video, lost-device waits and media
hang recovery, then system/runtime suspend and resume on both dies. Navi44
must keep JPEG static while VCN uses DPG.

## Not amdgpu, but seen during bring-up

- Intel display: the `DDI_AUX_CTL` sync-pulse fields and the
  `read_full_edid` segment pointer.
- MT7922 Wi-Fi: no hardware acceptance yet.
