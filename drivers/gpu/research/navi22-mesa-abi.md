# Navi22 (RX 6750 XT) — userspace ABI audit for Mesa 26.2.4 + libdrm 2.4.134

Scope: every kernel interface radeonsi and RADV (Mesa 26.2.4) and
libdrm_amdgpu 2.4.134 use during device initialisation and the first
submission on a GFX10.3 discrete GPU (Navi22, GC 10.3.2, PCI `1002:73df`
rev `0xc0`), what Linux answers for this ASIC, what NARF answers, and which
plan milestone owns each gap.

Sources (read-only reference; nothing from them was built or executed):

- Mesa 26.2.4 release tarball: `src/amd/common/ac_gpu_info.c`,
  `ac_linux_drm.c`, `ac_video.c`, `amdgpu_devices.c` (real-hardware INFO
  dumps, incl. Navi21), `src/gallium/winsys/amdgpu/drm/`,
  `src/amd/vulkan/winsys/amdgpu/`, `src/util/u_sync_provider.c`.
- libdrm 2.4.134 release tarball: `amdgpu/amdgpu_device.c`,
  `amdgpu_gpu_info.c`, `amdgpu_vamgr.c`, `data/amdgpu.ids`.
- Linux (`~/git/linux`, KMS 3.64.0): `amdgpu_kms.c` (`amdgpu_info_ioctl`,
  `amdgpu_hw_ip_info`, `amdgpu_firmware_info`), `amdgpu_drv.c`,
  `gfx_v10_0.c`, `nv.c`, `nbio_v2_3.c`, `amdgpu_discovery.c`, `amdgpu_vm.h`,
  `amdgpu_gmc.h`, `amdgpu_ctx.c`, `amdgpu_cs.c`, `amdgpu_gem.c`.

"Baseline" below is `claude/navi22-bringup` at `1d2a360c` (Navi48 merge +
Navi22 kernel queues + IH fence routing). Evidence level: source audit and
software models only; nothing here has run against a physical board.

## 1. Initialisation sequence and abort points

Both Mesa drivers enter through `ac_drm_device_initialize` →
`amdgpu_device_initialize` (libdrm), then `ac_query_gpu_info`. In order,
with what happens when the kernel answer is missing or wrong:

| # | Call | Required | Failure behaviour |
|---|------|----------|-------------------|
| 1 | `drmGetNodeTypeFromFd`; on a primary node `DRM_IOCTL_GET_CLIENT` (`amdgpu_get_auth`) | yes (primary only) | error → init fails |
| 2 | `DRM_IOCTL_VERSION` (`drmGetVersion`) | **yes** | libdrm dereferences the result unconditionally; ioctl failure ⇒ NULL deref in `_amdgpu_device_initialize`. Major must be 3 (else `-EBADF`). |
| 3 | `AMDGPU_INFO_ACCEL_WORKING` | **yes** | error, or value 0 ⇒ "`AMDGPU_INFO_ACCEL_WORKING = 0`", `-EBADF`; radeonsi falls back to another driver (llvmpipe), RADV reports no device |
| 4 | `AMDGPU_INFO_DEV_INFO` (`amdgpu_query_gpu_info_init`) | yes | init fails |
| 5 | `AMDGPU_INFO_READ_MMR_REG` 0x263e (GB_ADDR_CONFIG), count 1, instance 0xffffffff | **yes** on family ≥ AI | init fails (both libdrm and `ac_drm_query_gpu_info`) |
| 6 | `AMDGPU_INFO_HW_IP_COUNT(GFX)` then `HW_IP_INFO(GFX)` (`amdgpu_query_gfx_level_major`) | no | error ignored; selects the PRT half-VA split |
| 7 | VA manager from DEV_INFO `virtual_address_offset/max`, `high_va_offset/max`, `virtual_address_alignment` | yes (values) | zero ranges ⇒ every VA allocation fails later |
| 8 | `/usr/share/libdrm/amdgpu.ids` lookup by (`device_id`, `pci_rev`) | no | marketing name "AMD Unknown"; `73DF,C0` = "AMD Radeon RX 6750 XT" |
| 9 | `drmGetDevice2` (sysfs PCI bus info) | RADV yes, radeonsi no | RADV init fails |
| 10 | DRM minor ≥ 54 | **yes** | "only compatible with 3.54.0 (kernel 6.6+)" ⇒ fail |
| 11 | sync provider: `DRM_CAP_SYNCOBJ_TIMELINE` via `drmGetCap` | timeline optional | binary syncobjs are mandatory in practice (radeonsi creates one at winsys init, step 19) |
| 12 | `HW_IP_INFO` for every IP 0..9, `HW_IP_COUNT` for those that answered | per IP | an IP whose query fails is skipped |
| 13 | gfx or compute `available_rings` ≠ 0 | **yes** | "failed to find gfx or compute" ⇒ fail |
| 14 | `FW_VERSION` ME, MEC, PFP (index 0) | **yes** | any failure ⇒ fail |
| 15 | `FW_VERSION` VCN (only if VCN rings) | conditional | fail |
| 16 | `AMDGPU_INFO_MEMORY` | **yes** | fail |
| 17 | `ac_identify_chip`: (`family`, `external_rev`) and GFX `ip_discovery_version` | **yes** | "unknown (family_id, chip_external_rev)" / "Unknown gfx version" ⇒ unsupported HW |
| 18 | `AMDGPU_INFO_MAX_IBS` | no | falls back to 192/124/50 estimates |
| 19 | radeonsi: `DRM_IOCTL_SYNCOBJ_CREATE` (vm timeline syncobj) | **yes** | winsys creation fails |
| 20 | `DRM_CAP_ADDFB2_MODIFIERS` | no | modifiers disabled for WSI |

Baseline NARF stops at step 2 on Navi22: the amdgpu card has no KMS
`mode_state` until a display owner attaches one, so `DRM_IOCTL_VERSION`
returns an error and libdrm would dereference NULL. Navi48 attaches a
`Card::new("amdgpu", "AMD GPU", (3, 0, 0))` in `amdgpu_navi48_kms::with_card`
on first publication; Navi22 must reuse that path (display workstream,
milestone 4). With version 3.0.0 libdrm passes step 2, then step 3 declines
cleanly (ACCEL_WORKING = 0), and even if it did not, step 10 declines
(minor 0 < 54). Reporting `(3, 64, 0)` is the last switch to flip, together
with ACCEL_WORKING and `available_rings`, once milestone 8 lands.

## 2. DRM core requirements

| Interface | Linux | Mesa use | NARF baseline | Owner |
|-----------|-------|----------|---------------|-------|
| `DRM_IOCTL_VERSION` | `amdgpu` 3.64.0 | major==3, minor≥54; minor≥55 GPUVM_FAULT, ≥59 zero-VRAM default | Navi22: none (no mode_state). Navi48: 3.0.0 | M4 (card), M9 (minor) |
| `GET_CAP SYNCOBJ` | 1 | binary syncobj | 1 (generic table) | — |
| `GET_CAP SYNCOBJ_TIMELINE` | 1 | Vulkan timeline semaphores / radeonsi timeline fences | 1 on amdgpu (`drm_ioctl_bridge::amdgpu_cap_value`); 0 on virtio-gpu, as Linux | done (sync) |
| `GET_CAP ADDFB2_MODIFIERS` | 1 | `kernel_has_modifiers` | 0 | M4/M5 |
| `GET_CAP PRIME` | 3 | dma-buf export/import | 3 | — |
| `SYNCOBJ_{CREATE,DESTROY,WAIT,TIMELINE_WAIT,QUERY,TRANSFER,FD_TO_HANDLE,HANDLE_TO_FD,SIGNAL,RESET,TIMELINE_SIGNAL,EVENTFD}` | yes | init (radeonsi), every fence; EVENTFD: KWin explicit sync | all on amdgpu nodes (`drm::syncobj_ioctl`), Linux errnos; timeline payloads are `dma_fence_chain`s (`drm::syncobj::FenceChain`); fds via `IoctlContext` (opaque `syncobj_file`, `EXPORT/IMPORT_SYNC_FILE`) | done (sync) |
| `PRIME_HANDLE_TO_FD` / `FD_TO_HANDLE` | yes | WSI, DRI3 | generic PRIME table, not wired to amdgpu GEM | M8 |
| `GEM_CLOSE` | yes | every BO | `amdgpu_gem` | — |
| sysfs PCI info (`drmGetDevice2`) | yes | RADV required | `drm_sysfs_bridge` | — |

## 3. AMDGPU_INFO queries

| Query | Mesa/libdrm | Required | Linux Navi22 | NARF baseline | Owner |
|-------|-------------|----------|--------------|---------------|-------|
| ACCEL_WORKING | libdrm init | yes | 1 | 0 (deliberate) | M8 switch |
| DEV_INFO | both | yes | §4 | partial (§4) | M9 (this branch) |
| READ_MMR_REG | both | yes (0x263e) | §8 | EINVAL | M9 (this branch) |
| HW_IP_INFO | both | per IP | §5 | GC/SDMA only, wrong GFX `hw_ip_version`, wrong SDMA alignment | M9 (this branch) |
| HW_IP_COUNT | both | per IP | §5 | discovery block count | M9 (this branch) |
| FW_VERSION | ac_gpu_info | ME/MEC/PFP yes | §6 | EINVAL | M9 (this branch) |
| MEMORY | ac_gpu_info | yes | §7 | VRAM real; GTT 0 | M8 (GTT) |
| VRAM_GTT | `ac_drm_query_heap_info` | no (stats) | §7 | VRAM real; GTT 0 | M8 (GTT) |
| MAX_IBS | ac_gpu_info | no (fallback) | per-ring `(max_dw - frame)/ib_size` | EINVAL | M8 |
| TIMESTAMP | radeonsi query, RADV calibrated timestamps | no at init | `gfx_v10_0_get_gpu_clock_counter` (GOLDEN_TSC via SMUIO) | EINVAL | M9 |
| SENSOR (GFX_SCLK, GFX_MCLK, GPU_TEMP, GPU_LOAD, …) | HUD/queries | no | SMU metrics; `-ENOENT` without DPM | EINVAL | M10 |
| VRAM_USAGE, VIS_VRAM_USAGE, GTT_USAGE, NUM_BYTES_MOVED, NUM_EVICTIONS, NUM_VRAM_CPU_PAGE_FAULTS | HUD / budget (`VK_EXT_memory_budget`) | no | TTM counters | EINVAL | M8 |
| GPUVM_FAULT | RADV fault reporting (minor ≥ 55) | no | last fault (addr, status, vmhub) | EINVAL | M8 |
| VIDEO_CAPS | radeonsi VA-API only | no | VCN 3.0 codec table | Sienna Cichlid tables with the published VCN harvest (VCN0 table on this card) | M10 (done) |
| VBIOS (SIZE/IMAGE/INFO) | tools | no | VBIOS | EINVAL | M9 |
| UQ_FW_AREAS | only with `AMD_USERQ` | no | EOPNOTSUPP on gfx10 | EINVAL | — |
| GDS_CONFIG | none in 26.2.4 init | no | gds sizes | EINVAL | — |
| VCE_CLOCK_TABLE, NUM_HANDLES | none (no VCE/UVD) | no | — | EINVAL | — |

`AMDGPU_INFO` semantics both sides depend on: `return_size == 0 ||
return_pointer == 0` ⇒ EINVAL before the query is examined; replies are
copied as `min(return_size, sizeof(reply))`. NARF's `amdgpu_info::dispatch`
already mirrors both.

## 4. DEV_INFO field by field (`struct drm_amdgpu_info_device`)

Linux source column names the `adev` field `amdgpu_kms.c` copies. "Navi22"
is what Linux reports on a full (unharvested) Navi22; board-dependent values
come from discovery/fuses at runtime and are listed as the derivation.

| Field | Linux source | Navi22 (Linux) | Mesa reads it for | Baseline |
|-------|--------------|----------------|-------------------|----------|
| device_id | `pdev->device` | 0x73df | chip id, amdgpu.ids | ok |
| chip_rev | `rev_id` = NBIO `RCC_DEV0_EPF0_STRAP0.STRAP_ATI_REV_ID` (`nbio_v2_3_get_rev_id`) | strap (expected 0) | `chip_rev` | 0 (not read) |
| external_rev | `rev_id + 0x32` (`nv_common_early_init`, GC 10.3.2) | 0x32 + strap | **`ac_identify_chip`: NAVI22 range 0x32..0x3c** | 0 ⇒ Mesa "unknown chip" |
| pci_rev | `pdev->revision` | 0xc0 on this board | amdgpu.ids marketing name | 0 |
| family | `adev->family` | `AMDGPU_FAMILY_NV` (143) | identify | ok |
| num_shader_engines | gc_info `gc_num_se` | 2 | `max_se` | ok |
| num_shader_arrays_per_engine | `gc_num_sa_per_se` | 2 | `max_sa_per_se` | ok |
| gpu_counter_freq | `nv_get_xclk` = VBIOS gfx_info `rlc_gpu_timer_refclk` (×10 kHz) | 100000 (Navi21 dump) | `clock_crystal_freq`; 0 ⇒ warning, timestamps wrong | 0 — gap, M9 (VBIOS gfx_info parse) |
| max/min_engine_clock | DPM: `GetMax/MinDpmFreq(GFXCLK)` MHz ×1000 kHz | board PPTable | `max_gpu_freq_mhz` (heuristics, `max_gflops`) | 0 |
| max/min_memory_clock | DPM UCLK | board | `memory_freq_mhz` (bandwidth) | 0 — gap, M10 |
| cu_active_number | `gfx_v10_0_get_cu_info` (fuse+user WGP masks) | 40 | `num_cu` cross-check | discovery maximum |
| cu_ao_mask | same, `ao_bitmap << (se*16 + sh*8)` for se,sh < 2 | 0xffffffff | — | 0 |
| cu_bitmap[4][4] | same, `[se][sh]`, 2 bits per active WGP | 0x3ff per SA | **`cu_mask`, `num_cu`, enabled SE mask, scratch sizing** | 0 ⇒ Mesa computes 0 CUs |
| cu_ao_bitmap | same | 0x3ff per SA | — | 0 |
| enabled_rb_pipes_mask | `gfx_v10_0_setup_rb` | 0xff | `enabled_rb_mask` (occlusion queries, DB) | 0 |
| num_rb_pipes | `max_backends_per_se * max_shader_engines` | 8 | `max_render_backends` | ok |
| num_hw_gfx_contexts | `gfx_v10_0_gpu_early_init` | 8 | — | ok |
| pcie_gen, pcie_num_lanes | `amdgpu_device_get_pcie_info` (ASIC ∧ platform caps) | 4, 16 | bandwidth estimate | 0 — gap, M10 |
| ids_flags | FUSION no; PREEMPTION (`mcbp`, default off); TMZ (off by default on 10.3.2); TRUNC_COORD (gfx11 only); GANG_SUBMIT (always, bare metal) | `GANG_SUBMIT` | `has_dedicated_vram`, TMZ, reg shadowing | 0 |
| virtual_address_offset | `AMDGPU_VA_RESERVED_BOTTOM` | 0x10000 | VA manager | ok (shared Geometry) |
| virtual_address_max | `min(max_pfn*4K - RESERVED_TOP, HOLE_START)` | 0x8000_0000_0000 | VA manager | ok |
| high_va_offset / high_va_max | `HOLE_END` / `HOLE_END \| vm_size` | 0xffff_8000_0000_0000 / 0xffff_ffff_ffbf_0000 | VA manager | ok |
| virtual_address_alignment, gart_page_size | `max(PAGE_SIZE, 4096)` | 4096 | VA, GTT | ok |
| pte_fragment_size | `(1 << fragment_size) * 4096`, `amdgpu_vm_adjust_size(…, 9, 3, 48)` | 2 MiB | BO alignment | ok |
| ce_ram_size | `F32_CE_PROGRAM_RAM_SIZE` | 65536 | — (gfx10 CE unused by Mesa) | 0 |
| vram_type, vram_bit_width | `amdgpu_atomfirmware_get_vram_info` | 9 (GDDR6), 192 | bandwidth, `memory_bus_width` | 0 — gap, M9 |
| vce_harvest_config | VCE | 0 | — | ok (0) |
| gc_double_offchip_lds_buf | gc_info | 1 | tess | ok |
| wave_front_size | gc_info `gc_wave_size` | 32 | — | ok |
| num_shader_visible_vgprs | `gc_num_gprs` | 1024 | **VGPR budget** | ok |
| num_cu_per_sh | `max_cu_per_sh` = 2·(wgp0+wgp1) | 10 | `num_cu_per_sh` | ok |
| num_tcc_blocks | `gc_num_gl2c` | 12 | `max_tcc_blocks`, L2/L3 size (gfx10.3: L3 = tcc×8 MiB on Navi22) | ok |
| gs_vgt_table_depth, gs_prim_buffer_depth, max_gs_waves_per_vgt | gc_info | 32, 1792, 32 | GS ring sizing | ok |
| pa_sc_tile_steering_override | 0 for GC ≥ 10.3 | 0 | raster state | ok (0) |
| tcc_disabled_mask | `CGTS_(USER_)TCC_DISABLE` TCC/HI_TCC fields | 0 | `num_tcc_blocks = max - popcount` | 0 (not read) |
| tcp/sqc/gl1c/gl2c cache sizes | gc_info ≥ v1.2 | 0 on a v1.0/1.1 table (Navi21 dump: 0) | gfx ≥ 11 only | pass-through |
| mall_size | discovery MALL_INFO | 96 MiB expected | gfx ≥ 11 only | 0 — gap, M9 |
| enabled_rb_pipes_mask_hi | not set by `amdgpu_kms.c` | 0 | — | 0 |
| shadow/csa size/alignment | gfx11 `get_gfx_shadow_info` | 0 | — | 0 |
| userq_ip_mask | gfx10: none | 0 | only with `AMD_USERQ` | 0 |

The Mesa-critical fields that the baseline gets wrong for Navi22 are
`external_rev` (chip identification fails), `cu_bitmap` (zero CUs), and the
GB_ADDR_CONFIG read (§8); all three are implemented on this branch.

## 5. HW_IP_INFO / HW_IP_COUNT per IP

`amdgpu_hw_ip_info` reports the **IP-block** version (`ip_blocks[i].version`,
e.g. `gfx_v10_0_ip_block` = 10.0), not the discovery version, in
`hw_ip_version_major/minor`, and the discovery version in
`ip_discovery_version`. Mesa uses `ip_discovery_version` when non-zero
(10.3 ⇒ GFX10_3); libdrm also reads it from minor ≥ 48. An IP type whose
block is absent returns **success with an all-zero reply**; an unknown type
or `ip_instance ≥ 1` is EINVAL. `available_rings = (1 << min(entities,
ready rings)) - 1` with `amdgpu_ctx_num_entities` = {GFX 1, COMPUTE 4,
DMA 2, others 1}.

| IP | block | hw_ip ver | discovery ver | ib start/size align | available_rings (Linux) | HW_IP_COUNT (Linux) | Baseline |
|----|-------|-----------|---------------|----------------------|-------------------------|---------------------|----------|
| GFX | gfx_v10_0 | 10.0 | 0x0a0302 | 32/32 | 0x1 | 1 | ver 10.3 (wrong), rings 0, count = GC blocks |
| COMPUTE | gfx_v10_0 | 10.0 | 0x0a0302 | 32/32 | 0xf | 1 | same |
| DMA | sdma_v5_2 | 5.2 | 0x050202 | 256/4 | 0x3 | 2 | align 32/32 (wrong), count = SDMA0 blocks |
| UVD, VCE, UVD_ENC | absent | 0 | 0 | 0 | 0 | EINVAL | EINVAL |
| VCN_DEC | vcn_v3_0 | 3.0 | VCN inst 0 | 256/64 | 0x1 once VCN rings run | `num_vcn_inst` | 0x1 / 2 once the decode ring verified (accel only) |
| VCN_ENC | vcn_v3_0 | 3.0 | same | 256/4 | 0x1 | same | 0x1 / 2 once an encode ring verified |
| VCN_JPEG | jpeg_v3_0 | 3.0 | same | 256/64 | 0x1 | 1·1 | 0x1 / 1 once the JPEG ring verified |
| VPE | absent | 0 | 0 | 0 | 0 | EINVAL | EINVAL |

Mesa pads `ib_alignment` to ≥ 256 anyway, but the reply must still be the
Linux one because libdrm consumers and tools read it raw.

## 6. FW_VERSION (`drm_amdgpu_query_fw { fw_type, ip_instance, index }`)

`ip_instance ≠ 0` ⇒ EINVAL. Linux takes versions from the firmware file
headers at `init_microcode` time (`header.ucode_version`, plus the
type-specific feature word), except SMC, which `smu_cmn_check_fw_version`
overwrites with the running `GetSmuVersion` answer.

| fw_type | Linux source for Navi22 | Mesa use |
|---------|-------------------------|----------|
| GFX_ME / PFP / CE | `gfx_firmware_header_v1_0`: `header.ucode_version`, `ucode_feature_version` (+32) | **ME/PFP required**; `me_fw_feature ≥ 32` ⇒ 32-bit predication |
| GFX_MEC index 0 / 1 | mec / mec2 headers; index > 1 EINVAL; absent MEC2 ⇒ {0,0} | **required**; `mec_fw_version < 100` ⇒ taskmesh-indirect0 workaround |
| GFX_RLC | `rlc_firmware_header_v2_0` version / feature (+32) | — |
| RLC_RESTORE_LIST_CNTL/GPM/SRM | v2.1 fields at +108/+112, +124/+128, +140/+144 (header minor ≥ 1) | — |
| GFX_RLCP / RLCV | v2.3 only; else 0 | — |
| SDMA index 0..1 | `sdma_firmware_header_v1_0` version / feature (+32), same file for both | — |
| SOS | `header.ucode_version`, `sos.fw_version` (+32) | — |
| SMC | `GetSmuVersion` | — |
| VCN | `header.ucode_version`, feature 0 | **required when VCN rings exist** (decode/encode caps) |
| DMCUB | `header.ucode_version`, feature 0 | — |
| ASD, TOC, CAP, DMCU, GMC, VCE, UVD, MES_KIQ, MES, IMU, VPE | not loaded on MP0 11.0.11 / GC 10.3.2 ⇒ {0, 0} | — |
| TA (index = TA type) | versions inside `navy_flounder_ta.bin` | — |

Baseline: EINVAL for every type (versions parsed during PSP load, not
retained). This branch retains them from the validated cold-boot firmware
set and publishes them after the cold boot completes.

## 7. MEMORY and VRAM_GTT

[Linux `amdgpu_info_ioctl`](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_kms.c):
`vram.total = real_vram_size`; `usable = real − vram_pin_size −
AMDGPU_VM_RESERVED_VRAM (8 MiB)`; `max_allocation = usable * 3 / 4`;
`cpu_accessible.total = visible_vram_size`, `usable = min(visible −
visible_pin, vram.usable)`; GTT = TTM GTT manager size (`ttm_tt_pages_limit`
default: half of system RAM). VRAM_GTT is the same three usable numbers.

Mesa reads only `total_heap_size` of each heap ("usable_heap_size values can
be random"); it rounds VRAM up to 256 MiB, sets `all_vram_visible` when
visible ≥ 90 % (true on this board: ReBAR 16 GiB BAR over 12 GiB VRAM), and
uses `gtt.total` as `gart_size_kb`. GTT = 0 does not abort init, but every
GTT placement (staging, CPU-visible descriptors, fences) then fails.

Current implementation: physical VRAM totals come from probe. Live opens use
their card's registered client heap for usable VRAM and its current usage;
without that heap the Navi22 snapshot reply subtracts the 8 MiB reservation.
GTT capacity is GEM's actual shared system-memory limit (half of RAM), and
usage is GEM's live backing count, including retained objects after handle
closure. VRAM_GTT reports the same usable sizes. VRAM_USAGE, VIS_VRAM_USAGE
and GTT_USAGE expose the corresponding byte counts through the open's ioctl
dispatcher. The native Rust regression exercises both RDNA2 and RDNA4, real
GEM allocation/release, shared ownership, hidden-pool usage and short copies.

## 8. READ_MMR_REG

`nv_read_register` allowlist (absolute dword offsets via `SOC15_REG_ENTRY`,
GC base 0x1260/0xA000, SDMA via GC banks): GRBM_STATUS, GRBM_STATUS2,
GRBM_STATUS_SE0..3, SDMA0/1_STATUS_REG, CP_STAT, CP_STALLED_STAT1..3,
CP_CPF_BUSY_STAT, CP_CPF_STALLED_STAT1, CP_CPF_STATUS, CP_CPC_BUSY_STAT,
CP_CPC_STALLED_STAT1, CP_CPC_STATUS, **GB_ADDR_CONFIG** (0x1260 + 0x13de =
**0x263e**, answered from the cached `gfx.config.gb_addr_config`).
Rules: `count > 128` ⇒ EINVAL; SE/SH index field all-ones = broadcast, else
≥ `AMDGPU_GFX_MAX_SE` (4) / `MAX_SH_PER_SE` (2) ⇒ EINVAL; a non-allowlisted
offset ⇒ **EFAULT**; reply copied `min(return_size, count*4)`.

Mesa 26.2.4 on GFX10.3 issues exactly one read at init: 0x263e, count 1,
instance 0xffffffff (the GFX6–8 raster/tile reads are gated on family < AI).
The value feeds `num_tile_pipes`, the asserted 256 B pipe interleave, and the
DCC/tiling modifier `PIPE_XOR_BITS`/`PACKERS`, so it must equal what the
display side (`amdgpu_display.c` modifier list) uses. The live-status
registers are diagnostics (radeonsi HUD, `umr`-style tools).

Baseline: EINVAL. This branch answers GB_ADDR_CONFIG from the value the cold
boot captured; the live-status entries return EFAULT until a retained GC
reader exists (M9) — they need MMIO, which the cold-boot owner holds
exclusively.

## 9. SENSOR, VIDEO_CAPS

SENSOR returns `-ENOENT` on Linux when DPM is not enabled and per-sensor
values otherwise (sclk/mclk MHz, temperature m°C, load %). Mesa uses it only
for the HUD/`GALLIUM_HUD` and `VK_AMD`-style queries; failure is tolerated.
VIDEO_CAPS (decode/encode codec limits) is read only by radeonsi's VA-API
path; Mesa 26.2.4 computes the VCN 3.0 caps itself in `ac_fill_video_info`
once VCN rings are advertised. Both are M10. VIDEO_CAPS now answers the
Sienna Cichlid tables with `harvest_config` applied; the VCN/JPEG rings are
client-submittable through `amdgpu_vcn_navi22_cs` behind
`amdgpu.navi22_accel` (see `docs/MESA_AMD.md` for the VA-API/Vulkan video
userspace).

## 10. Memory and submission ioctls

| Ioctl | Mesa use on GFX10.3 | Linux contract | Baseline | Owner |
|-------|---------------------|----------------|----------|-------|
| GEM_CREATE | domains VRAM, GTT, VRAM\|GTT, GDS/OA (GDS only for NGG streamout on gfx10), DOORBELL (userq only); flags CPU_ACCESS_REQUIRED, NO_CPU_ACCESS, CPU_GTT_USWC, VRAM_CLEARED, VM_ALWAYS_VALID, EXPLICIT_SYNC, DISCARDABLE (gfx10.3 BIG_PAGE), ENCRYPTED (TMZ only) | `AMDGPU_GEM_CREATE_SETTABLE_MASK`, domain validation, alignment, `VM_ALWAYS_VALID` requires the creating `drm_file`'s VM | parses/validates like Linux; backing is contiguous **system** memory whatever the domain; GDS/OA refused | M8 (vm + GEM backend) |
| GEM_MMAP | every CPU map | fake offset | handle<<12 offset | M8 (VRAM BAR mapping) |
| GEM_VA (MAP/UNMAP/CLEAR/REPLACE) | every BO; flags READABLE/WRITEABLE/EXECUTABLE, MTYPE_UC, PRT (sparse, RADV), DELAY_UPDATE | per-`drm_file` VM, `AMDGPU_GMC_HOLE_MASK`, 4 KiB alignment | GMC11-shaped validation and page tables, not bound to a VMID | M8 (vm workstream: GMC10 PTE, VMID 1–15) |
| DRM_AMDGPU_VM (RESERVE/UNRESERVE_VMID) | RADV SQTT only | reserved VMID | not dispatched | M9 |
| GEM_METADATA (SET/GET) | radeonsi/RADV on every exported/imported BO; `tiling_info` uses `AMDGPU_TILING_SWIZZLE_MODE`, `DCC_OFFSET_256B`, `DCC_PITCH_MAX`, `DCC_INDEPENDENT_64B/128B`, `DCC_MAX_COMPRESSED_BLOCK_SIZE`, `SCANOUT`; plus ≤ 256 B UMD metadata | stored on the BO, returned on import | EINVAL | M8 (GEM backend), M4 for scanout consumption |
| GEM_OP GET_GEM_CREATE_INFO | import path | returns size/alignment/domains/flags | implemented | — |
| GEM_WAIT_IDLE | BO idle waits | waits on the BO's reservation fences | always idle | M8 |
| GEM_USERPTR | `EXT_external_memory_host`, radeonsi userptr | pins user pages into GTT | EINVAL | M8 (needs GART) |
| BO_LIST | not used (radeonsi/RADV use the BO_HANDLES chunk) | `amdgpu_bo_list_ioctl` | CREATE/UPDATE/DESTROY with Linux errnos (`amdgpu_bo_list`); CS accepts `bo_list_handle` | done (sync) |
| CTX ALLOC/FREE | per context, priority LOW/NORMAL/HIGH (HIGH needs `CAP_SYS_NICE` or master ⇒ EACCES, radeonsi retries NORMAL) | | implemented (bookkeeping) | — |
| CTX QUERY_STATE2 | robustness, reset status (`RESET`, `RESET_IN_PROGRESS`, `GUILTY`, `VRAMLOST`) | | always "no reset" | M10 |
| CTX SET/GET_STABLE_PSTATE | profiling only | SMU | recorded, not applied | M10 |
| CS | chunks IB (flags PREAMBLE, PREEMPT, TC_WB_NOT_INVALIDATE), BO_HANDLES, FENCE (user fence BO), SYNCOBJ_IN/OUT, SYNCOBJ_TIMELINE_WAIT/SIGNAL; radeonsi also uses a temporary context for a NOP probe (`BO_HANDLES`+`IB`) | `amdgpu_cs_ioctl` | every listed chunk accepted with Linux errnos (§12); CP_GFX_SHADOW (gfx11) EINVAL | done (uapi, sync) |
| WAIT_CS, WAIT_FENCES, FENCE_TO_HANDLE | `ac_drm_cs_query_fence_status` (WAIT_CS), sync_file export | per-context fence seq | WAIT_CS resolves the IP/ring and refuses never-emitted handles (EINVAL); WAIT_FENCES all/any with `amdgpu_gem_timeout`; FENCE_TO_HANDLE SYNCOBJ / SYNCOBJ_FD / SYNC_FILE_FD | done (sync) |
| SCHED (override priority) | compositors only | master | not dispatched | — |
| USERQ / USERQ_SIGNAL / USERQ_WAIT | only with `AMD_USERQ` and a non-zero `userq_ip_mask` | gfx11+ | not dispatched | — (gfx10 has no user queues) |

## 11. Gap ownership summary

| Gap | Blocks | Owner |
|-----|--------|-------|
| amdgpu card `mode_state` (DRM_IOCTL_VERSION) on Navi22 | libdrm init (NULL deref) | M4 display (reuse `amdgpu_navi48_kms` card publication) |
| DRM minor 64, ACCEL_WORKING 1, available_rings, HW_IP_COUNT | Mesa init | M8 — one switch, `amdgpu_info_navi22::SUBMISSION` |
| per-file syncobj table on amdgpu nodes, timeline cap | radeonsi winsys init, every fence | M8 |
| GTT/GART heap, GEM_USERPTR | GTT BOs | M8 vm |
| GEM VRAM placement, BAR mapping, pinned accounting, metadata | first BO | M8 |
| GEM_VA bound to a per-client VMID (GMC10 PTEs) | first draw | M8 vm |
| CS on native queues, fences, WAIT_CS | first submission | M8 (rings owners exist) |
| MAX_IBS, TIMESTAMP, usage counters, GPUVM_FAULT | optional | M8/M9 |
| gpu_counter_freq, vram_type/width, mall_size, pcie_gen/lanes, memory clocks | heuristics only | M9/M10 |
| SENSOR, VIDEO_CAPS, VCN rings and FW_VERSION(VCN) relevance | HUD, video | M10 |
| DEV_INFO identity/topology, HW_IP_INFO, FW_VERSION, READ_MMR_REG(GB_ADDR_CONFIG), MEMORY rounding | Mesa init correctness | **this branch** |

## 12. Status on `claude/navi22-uapi`

Navi 22 now plugs into the generic `amdgpu_cs` / `amdgpu_gem` / `amdgpu_vm`
render path that Navi48 introduced (origin/main #624): the card registers an
`amdgpu_cs::Submitter` (`amdgpu_navi22_cs`) and a client VRAM heap once its
kernel queues pass their ring/IB tests. Implemented (software models only):

| Item | Where | Notes |
|------|-------|-------|
| `GET_CLIENT` on primary nodes | `drm_ioctl_bridge::get_client` | `drm_getclient`: idx 0 → auth (current master), pid, `overflowuid`; else EINVAL; render nodes EACCES |
| `DRM_IOCTL_VERSION` | `amdgpu_info_navi22::drm_version`, `drm_ioctl_bridge::without_kms` | `amdgpu` 3.64.0 on Navi22 while `SUBMISSION` is wired; answered on both nodes even before a KMS owner attaches state (libdrm dereferences the result) |
| `GET_CAP` without KMS state | `drm_ioctl_bridge::without_kms` | the amdgpu table (`drm_ioctl_bridge::amdgpu_cap_value`): SYNCOBJ 1, SYNCOBJ_TIMELINE 1, PRIME 3 |
| ACCEL_WORKING, DEV_INFO, READ_MMR_REG 0x263e, HW_IP_INFO/COUNT 0–9, FW_VERSION, MEMORY, VRAM_GTT, VIDEO_CAPS (192 B), MAX_IBS (40 B) | `amdgpu_info_navi22` | §3–§8; ACCEL/rings/counts/GANG_SUBMIT follow `SUBMISSION` (wired) and the cold boot's ring/IB proof |
| Live MEMORY/VRAM_GTT, VRAM_USAGE, VIS_VRAM_USAGE, GTT_USAGE | `amdgpu_info::dispatch_for` | registered client VRAM heap and shared GEM system-memory budget; retained owners still count after handle closure |
| CTX | `amdgpu_ctx` | priority permits as Linux (HIGH needs CAP_SYS_NICE or master → EACCES); QUERY_STATE/QUERY_STATE2 report GPU recoveries (`UNKNOWN_RESET`, `RESET`+`VRAMLOST`) |
| GEM_CREATE (VRAM heap / system), GEM_MMAP, GEM_VA, GEM_WAIT_IDLE, GEM_OP, GEM_CLOSE | generic `amdgpu_gem` / `amdgpu_vm` | Navi22 registers its heap from the cold-boot pool; GEM_MMAP's out arm fixed to offset 0 of the 8-byte union |
| GEM_METADATA | generic `amdgpu_gem` | stored on the object, visible to PRIME importers |
| PRIME export/import of amdgpu GEM objects | `drm_devfs_bridge` (`AmdgpuDmaBufFile`) | same-driver dma-buf with a shared reservation; jobs listing it in BO_HANDLES fence it (implicit sync) |
| CS: IB, BO_HANDLES, SYNCOBJ_IN/OUT, DEPENDENCIES, FENCE | generic `amdgpu_cs` + `amdgpu_navi22_cs` | user fence (4 KiB BO) written by the CPU when the job retires; IBs on gfx ring 0, compute 0–3 (one queue), SDMA 0/1 |
| WAIT_CS, SYNCOBJ_* (binary) | generic | SYNCOBJ_WAIT timeout now `-ETIME`, unsubmitted without WAIT_FOR_SUBMIT `-EINVAL` (Linux) |
| Timeline syncobjs, `DRM_CAP_SYNCOBJ_TIMELINE` = 1 | `drm::syncobj` (`FenceChain`, `find_seqno`, `query_point`), `drm::syncobj_ioctl` | TIMELINE_WAIT (WAIT_FOR_SUBMIT / WAIT_AVAILABLE), QUERY (LAST_SUBMITTED), TRANSFER, TIMELINE_SIGNAL; unordered points start a new run as `dma_fence_chain_init`; waits park the syscall for an interruptible re-execution |
| Syncobj / sync_file fds | `drm::syncobj_ioctl` | HANDLE_TO_FD / FD_TO_HANDLE opaque fds name the same object across opens; EXPORT_SYNC_FILE / IMPORT_SYNC_FILE (with TIMELINE points); a job's sync_file leaf is the job itself (`poll`, FILE_INFO, MERGE from the syscall layer's `DrmSyncFile`); dma-buf EXPORT/IMPORT_SYNC_FILE on amdgpu dma-bufs reach the shared reservation |
| SYNCOBJ_EVENTFD | `drm::syncobj_ioctl` | a watcher task signals the eventfd when the point is available / signalled |
| CS `SYNCOBJ_TIMELINE_WAIT` / `_SIGNAL` | generic `amdgpu_cs` | one post-dependency chunk; unknown out-syncobj EINVAL; WAIT_FOR_SUBMIT waits up to 5 s (ETIME); dependencies on never-emitted jobs EINVAL |
| WAIT_FENCES, FENCE_TO_HANDLE, BO_LIST | generic `amdgpu_cs`, `amdgpu_bo_list` | Linux semantics and errnos; answered with or without a card engine |
| Implicit sync | generic `amdgpu_cs` | as `amdgpu_cs_sync_rings`: listed BOs and the user-fence BO, skipping the open's own jobs (`AMDGPU_SYNC_NE_OWNER`) and EXPLICIT_SYNC BOs; unlisted BOs get no fence; GEM_WAIT_IDLE waits for the space's jobs only on VM_ALWAYS_VALID BOs (the root reservation) |

Current gaps: native reset fence errors, GDS/GWS/OA, RDNA2 TIMESTAMP/SENSOR,
movement/eviction counters and tiled RDNA2 scanout. The older gap list's
GEM_USERPTR, PRT/sparse, SET_PLACEMENT, linear KMS modifiers, per-client
VMID/PASID and GPUVM_FAULT now have implementations and model coverage.
MEMORY/VRAM_GTT and the three memory-usage queries now report GEM's real
heaps/accounting. VCN/JPEG submission and its MMHUB VMID/PASID mapping are
wired (`amdgpu_vcn_navi22_cs`). Mesa and media hardware acceptance remain
separate bench work; this source audit does not establish them.

## 13. Navi 22 card backend design

**Memory.** GEM objects are the generic `amdgpu_gem::GemObject`: VRAM
reservations in the card's client heap (half the cold-boot pool's free
VRAM, published so no owner recycles it; entries carry
`address - fb + offset` from `Gmc::framebuffer`), or scattered system
pages charged to GEM's shared GTT budget. The heap survives GPU recovery and
is re-registered with the new owner.

**VA.** Each open's address space is the generic `amdgpu_vm::VmState`
(GMC10's Nv10 PTE format; tables in system memory, PDEs SYSTEM|SNOOPED).
`amdgpu_navi22_cs` leases GFXHUB contexts from `amdgpu_gmc_navi22` and
assigns them per client/job through `VmidManager`; media has a separate
MMHUB manager. Ring-side VM flushes write the job's root
(`VmState::root_pde`), invalidate it and update the PASID mapping. Separate
VM writebacks and active job fences control safe VMID reuse.

**Submission.** `amdgpu_cs::dispatch_async` validates (IBs inside the
caller's mappings, BO list, syncobjs, dependencies, user fence) and calls
`Submitter::submit`, which takes the platform owner, queues the IBs with
`ColdBoot::submit` (pipeline sync, VM flush on the ring's GFXHUB engine,
CONTEXT_CONTROL/FRAME_CONTROL on gfx, IBs with the VMID, ring fence) and,
when two jobs are already in flight on that ring, waits for the older one
without the owner and retries.

**Fences.** Tickets are `ring << 32 | sequence`, the ring index tagged with
the recovery epoch. `FenceReader` samples each queue's fence writeback with
its own capability and an HDP invalidate, so `signalled`, WAIT_CS and
syncobj `JobFence`s never take the owner; each sample retires the job
memory and user fences of completed jobs. After a recovery the submitter is
re-registered; older tickets read as complete (abandoned) and contexts
report the reset.
