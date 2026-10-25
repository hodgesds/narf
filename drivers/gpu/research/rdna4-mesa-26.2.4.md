# RDNA4 application and codec follow-up — Mesa26.2.4

Source audit, 2026-10-21. No physical rendering or codec acceptance is
claimed. This updates the historical Mesa26.0/DRM3.42 plan; it does not
change the native card's DRM3.0.0 or ACCEL_WORKING=0 gates.

The repository build selects Mesa26.2.4 and libdrm2.4.134 in
`verification/data/musl-demo/REGEN_mesa_amd.sh`. The official source archive
is <https://archive.mesa3d.org/mesa-26.2.4.tar.xz>, verified against that
recipe's SHA256:
`bce5f7fbebb934373b86c999a064d52fb5065878dc57f287f95346648ec832e9`.
The former source-extraction/host-shim replay is removed. Native Rust tests
exercise the actual INFO dispatch, query construction and owner admission.
Selected Mesa/libdrm must run against the real NARF device/ioctl boundary for
external compatibility acceptance. No physical execution is claimed here.

## Loader contract source audit

The real production refusal is earlier than a RADV KHR_display-only check:
`ac_drm_device_initialize` calls libdrm `amdgpu_device_initialize`, then
`_amdgpu_device_initialize` calls `amdgpu_query_info(ACCEL_WORKING)` and returns
`-EBADF` for zero. DRM 3.54 with unchanged acceleration zero still fails there.
DRM 3.0 with only a host acceleration override passes libdrm but fails Mesa
`ac_query_gpu_info`'s minor54 check. Both production gates stay unchanged.

Omitting DEV_INFO, GB_ADDR_CONFIG, usable graphics/compute HW_IP information,
MEMORY or any mandatory CP/VCN firmware answer fails at the actual consumer.
Actual VCN metadata withdrawal or an unsupported VCN IP fails the mandatory
firmware query while its ring is exposed; a withdrawn media owner correctly
permits graphics-only initialization without a VCN firmware query. MAX_IBS
refusal is optional to Mesa and takes its own fallback. NARF still supplies
its actual bound, preventing that larger fallback from becoming an assumed
submission capacity. The source audit is guidance for remaining implementation review; actual
userspace initialization, API rendering and physical acceptance remain open.

Raw VCN firmware interface minors8/9/10/11 reach Mesa unchanged. Selected Mesa
`radeon_vcn_enc_5_0.c:988–994` chooses min(reported minor,10), so1.8 selects1.8.
The AVC IGT proof now selects the retained authenticated interface the same
way as HEVC/AV1: major1, minor>=8, clamped to1.10. Missing or unsupported
interface is refused before fresh allocation or publication; preclaimed
unpublished storage is preserved. Reviewed IGT1.9 command data and the native Rust version-selection tests
cover1.8/1.9/1.10 headers, including rawminor11 clamping. Native-model regressions cover all sessions, restart, cancellation
and no-side-effect refusal. This fixes software interface selection; no
physical compatibility or capability follows from internal INFO models.

## Application software requirements

- `src/amd/common/ac_gpu_info.c::ac_query_gpu_info`, lines1471–1477,
  refuses DRMminor<54. Advertising3.42 would still fail initialization. At1496, user queues remain opt-in through AMD_USERQ and the device's
  `userq_ip_mask`; they are separate from normal graphics/compute CS.
- At1539–1546, a nonzero VCN decoder or unified ring additionally requires
  `FW_VERSION/FW_VCN`; otherwise common GPU initialization fails before
  creating a renderer. Native INFO now returns the raw VCN common-header
  `ucode_version` and zero feature, matching Linux `amdgpu_vcn_setup_ucode`
  and `amdgpu_firmware_info`. Its metadata is tied to the retained container
  whose payload PSP accepted, complete GC12 boot/TMR ownership, and the
  current proven client media owner. Missing, stopped or unproven media
  remains EINVAL; reset withdraws it before awaiting. No DRMminor or codec
  capability is raised by this query fix.
- `src/amd/vulkan/winsys/amdgpu/radv_amdgpu_cs.c`, lines1007–1118,
  builds gang leader/follower IBs. The last CS is the leader; mixed IPs
  become IB chunks in one request, with the last IB matching the request's
  IP (lines1754–1773). The follow-up native submitter now stages graphics
  and compute together, publishes the follower first, aggregates both
  physical completions and quarantines a partially published pair. Other
  mixed-engine groups stay refused. Raising DRMminor still requires the
  remaining selected-userspace contracts and physical gang acceptance.
- The Mesa feature thresholds still matter: GPUVM fault query55,
  GFX12 display DCC58, default zeroVRAM59 and write-compress-disable60
  (`ac_gpu_info.c`, lines1085,1158–1166). A larger DRMminor is not just
  a loader string; each enabled contract needs an implementation audit.
- Kernel VMID0 compute proof is separate from the opt-in client-space
  diagnostic. The latter exercises actual owned GEM/context/VM roots and
  native VMID/PASID Job submission on both graphics and compute queues. Its Rust models are internal software evidence. Real completion/readback remains a physical test. It does not establish
  a rendered image, texture/resource coverage, Mesa API conformance,
  compositor presentation or application rendering-to-scanout ordering.
- The opt-in native rectangle diagnostic uses reviewed fixed shader/PM4 data
  originating from Mesa26.2.4 META `CmdClearAttachments`, ACO NGG/PS and
  Addrlib3 layout. Its source pins and upstream license are retained in
  `tests/gfx12_render/README.md`; no compiler/shim regeneration gate remains.
  The model's explicit target/SE inputs are not captured board profiles.
  Native client roots check ownership, rendered/untouched pixels and guards,
  while failure/cancellation retain resources until proven reset. Physical
  image execution, Mesa API conformance and capability promotion remain open.

Local Linux primary paths are
`/usr/src/linux/drivers/gpu/drm/amd/amdgpu/{gfx_v12_0.c,gmc_v12_0.c,amdgpu_cs.c,amdgpu_job.c}`. The GC12 header contract is shared by GC12.0.0 and12.0.1.

## Codec work versus transport work

VCN5 unified client submission and JPEG5 kernel-filtered client IBs already
exist. Generic VCN submission forwards client MMHUB-VMID IBs and does not
implement a separate AVC-only codec command parser. Codec messages and
reference-picture management are generated by userspace/firmware:
Mesa26.2.4 `src/amd/common/ac_vcn_dec.c` has HEVC, VP9 and AV1 paths;
`ac_vcn_enc.c` selects VCN5 HEVC and AV1 command IDs, while
`src/gallium/drivers/radeonsi/mm/radeon_vcn_enc_5_0.c` supplies VCN5 encode
parameters. The current driver must not invent new per-codec transport
queues merely because a proof direction is still missing.

The follow-up adds separate original HEVC Main8/NV12 and Main10/P010 IDR
proofs with owned picture/reference/feedback/output arenas, full output
comparison, retained results and recovery reproof. Their builders match the
unchanged Mesa messages and independently decoded fixtures. These are
software checks until native completion runs on silicon; they do not enable
HEVC advertisement. VP9/AV1 decode and HEVC/AV1 encode still need their own
known-stream proofs and corresponding ownership and output checks.
The current advertised bits cover AVC decode,
AVC encode and JPEG decode only, and publish only after their native proof
passes on the live client transport. Linux `soc24.c` supplies the codec
limits; its arrays alone are not execution evidence.

Existing AVC encoding verifies bounded output and SPS/PPS/IDR/I-slice
headers. It is not a complete encode-to-decode round trip or a fidelity
check. The fixed AVC and JPEG decode proofs check decoded output and all
owned guards, but profile/range conformance, multi-client codec concurrency,
malformed-stream hardware behavior and VA-API/Vulkan-video end-to-end
acceptance still need physical testing. IGT2.4's `tests/amdgpu/amd_vcn.c`
provides the current AVC fixture; no HEVC/VP9/AV1 fixture was found there.
An additional codec proof needs a pinned known stream, expected decoded
pixels and Mesa/firmware message reference before enabling its capability.

The general video acceptance script in `REGEN_amd_gl_rootfs.sh` was written
for Navi22 and currently requires HEVC/AV1 decode. A Navi4 acceptance run
must account for its proven advertised directions, while checking that
unsupported directions remain absent. This is a test-policy gap, not
permission to broaden codec exposure.
