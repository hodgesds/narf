# drivers/gpu — Specification

> Status: **v1.0** (Stage 4 design lock). v0.1 outlined the
> minimum-viable presentation surface; v1.0 locks the in-tree
> vs userspace split, the minimum-viable terminal path, and
> ABI versioning.

## 1. Purpose & scope

The GPU subsystem is split into two phases. **Stage 4 ships only Phase A.**
Mixing them is a documented anti-goal — if you find yourself building
a compositor before a framebuffer works, stop.

### Phase A — simple framebuffer (Stage 4 v1)

- BAR mapping for the linear framebuffer.
- Mode set (resolution + format negotiation; no acceleration).
- Linear scanout (CPU writes pixels, GPU displays them).
- Stage-4 exit criterion: a Rust binary writes pixels and they appear.

### Phase B — accelerated path (post-Stage-4)

- Command buffer submission, per-queue rings.
- P2P DMA fast path (NIC → GPU, NVMe → GPU).
- 3D / Virgil3D / WebGPU equivalents.
- Out of scope for Stage 4.

**Owns (across both phases):** GPU device bring-up, DMA buffer
management tied to `io/` (P2PDMA Phase B only), submission
infrastructure (Phase B).

**Does NOT own:** Compositor, graphics APIs (Vulkan, OpenGL), font rendering.

## 2. Assumptions

- `memory/` has a dedicated domain for the GPU driver.
- **P2P DMA is an *optional* optimisation, not a requirement.** When
  `io::p2p_available(src, dst)` returns false (typical in QEMU and
  on consumer-class boards without ACS support across the relevant
  bridges), the driver MUST fall back to CPU-mediated copies through
  a bounce buffer. CI runs against virtio-gpu in QEMU where P2P is
  always unavailable; treating P2P as required would make CI a lie
  and ship a driver that only works on a narrow hardware subset.

## 3. Public interface

### AMD discrete PCIe probe and VRAM

`AmdGpu::bring_up` supports discovery outside the CPU-visible BAR0 aperture.
The default discovery table is a 10 KiB read beginning 64 KiB below the end
of **physical VRAM**, sized from the absolute `RCC_CONFIG_MEMSIZE` register
(BAR5 byte offset `0x378c`, value in MiB). The read uses BAR0 only within its
mapped length, then BAR5's MM_INDEX/MM_INDEX_HI/MM_DATA memory access ports.
Memory indices use byte addresses and a 31-bit split, including addresses
above 4 GiB. Reads validate alignment, arithmetic, physical VRAM bounds and
register-window capacity before accessing the device. They preserve the
index latches and never write the memory data port or resize a BAR. Probe
holds exclusive mapping/latch ownership and checks live PCI authority for
sizing and discovery. Missing or invalid tables leave discovery unavailable.

`VramInfo::size` is physical VRAM; `visible_size` is the smaller of that size
and the mapped BAR0 length. A 12 GiB RX 6750 XT with a 256 MiB BAR therefore
reports 12 GiB total and 256 MiB CPU-accessible; a 16 GiB Resizable BAR reports
12 GiB for both. This mapping bound also applies to APUs under passthrough.
Zero/absent VRAM has no visible heap and `fully_visible()` returns false.
The bare-metal APU aperture expansion and relocated/system-memory discovery
tables remain unimplemented.

`AmdGpu::is_apu()` uses the discovered GC version, falling back to
`ChipInfo::is_apu()` before discovery. The PCI fallback includes Rembrandt
and Raphael despite their coarse Navi register-family assignment. BAR size
never determines APU identity. `AMDGPU_INFO_MEMORY` and `VRAM_GTT` expose
the two memory sizes, and `DEV_INFO` sets FUSION only for an APU.
Navi 22 (`1002:73df`, GC 10.3.2) reports `AMDGPU_FAMILY_NV` and the GMC10
48-bit VA geometry, which matches GMC11's geometry. A missing or mismatched
GC version rejects its `DEV_INFO`. This identifies the device; acceleration
continues to report unavailable. Navi 22 firmware, GMC/GFX10 execution and
DCN3.0 display bring-up are not enabled by this probe path.

### Navi 22 PSP secure-OS bootstrap

`amdgpu_psp_boot::Firmware::open(gpu, registry_cap)` selects
`amdgpu/navy_flounder_sos.bin` only for `1002:73df`, GC 10.3.2 and MP0
11.0.11. Duplicate/missing IP instances and undersized register banks reject
the path. The registry and blob are read inside `Cap::invoke`; a bounded,
validated copy outlives those invocations. `amdgpu_psp_firmware::Image::parse`
supports PSP 11.0 container headers v1.0–v1.3, validates file/payload sizes
and descriptor bounds/overlap, and exposes KDB, SPL, system driver and SOS
in boot order. Parsing is structural validation; authentication remains with
the firmware registry and PSP. Optional KDB/SPL may be absent. TOC/RL and
alternate images are validated but not submitted by this bootstrap.

`unsafe amdgpu_psp_boot::Bootloader::new(gpu, pci_cap, pool)` requires an
exclusively owned physical GPU, permanent mappings, already trained VRAM,
and an owned `amdgpu_vram::Pool` with valid GPU addresses and exclusions
for firmware/scanout/discovery/training/TMR. It checks the pool's CPU mapping
against the visible BAR0 aperture and reserves a 1 MiB buffer aligned to
1 MiB in GPU address space. Construction performs no MMIO. The caller must
exclude other PSP clients, reset, memory training and power transitions.

`Bootloader::load(&Firmware).await` clears and copies each signed component
in cooperative 4 KiB chunks, drains posted VRAM writes, then supplies the
**GPU** address shifted by 20 to C2PMSG36 and the boot command to C2PMSG35.
These registers use MP0 base index 0. Each I/O batch checks current PCI
authority. Response waits use timer futures with 1 s deadlines; SOS startup
includes the required 20 ms delay and a changing, nonzero C2PMSG81 heartbeat.
An already running SOS is checked without upload. All-ones reads, rejection,
timeout and revocation fail closed. The object transitions
`Prepared → Loading → Ready | Failed`; a cancelled future remains `Loading`
and cannot be retried. Dropping an unpublished/completed staging reservation
releases it; uncertain device ownership quarantines it, including after
cancellation. No implicit reset or recovery reuses that memory.

Success proves only SOS liveness, not the identity/version of a previously
running SOS or availability of graphics acceleration. It does not set
`AmdGpu::fw_loaded`. The legacy single/multi-blob loaders reject Navi 22;
automatic platform wiring, VRAM training and the remaining IP firmware loads
remain follow-up work. The PSP11 ring and SMC loader below are explicit APIs.

### Navi 22 PSP command ring and trusted memory

`unsafe amdgpu_psp_ring::Psp::new_navi22(gpu, pci_cap, pool)` claims the sole
PSP 11.0.11 GPCOM ring under the exclusive ownership, trained-VRAM and permanent
mapping requirements of the bootstrap. A bootstrap owner must reach `Ready`
and be dropped before claiming the ring; failed/cancelled bootstrap requires
independent reset/recovery. PCI ID `1002:73df`, GC 10.3.2, MP1 11.0.11 and
SDMA0 5.2.2 are required; register banks are pinned to MP0 index 0,
NBIO 2.3/3.3 index 2 and HDP 5.0
index 0. NBIO remaps the HDP flush hole at BAR5 `0x7f000`; HDP read-cache
invalidation precedes fence/reply reads. The remap must verify before any ring
address is published. Missing/duplicate IPs and truncated windows reject the
constructor. No DCN/display discovery is needed.

The constructor reads GMC10 `GCMC_VM_FB_LOCATION_BASE/TOP` and `FB_OFFSET`
at GC index 0, dwords `0x16fc/0x16fd` and `0x16e7`, under the PCI capability.
It checks the owned pool's GPU addresses and CPU mapping against both the
framebuffer range and visible BAR0 size before allocating the ring. Ring and
payload addresses are GPU MC addresses. TMR's additional physical address is
`gpu_address - framebuffer_base + framebuffer_offset`, as seen by the GPU;
the host PCI BAR address is never substituted.

`start().await` uses the same bounded PF GPCOM wire protocol and 20 ms handshake
as the Phoenix transport. `setup_tmr_navi22(&amdgpu_psp_boot::Firmware).await`
uses `Image::toc()` from the validated SOS container, submits `LOAD_TOC`, and
allocates the PSP-reported TMR size (nonzero, page-aligned, at most 64 MiB).
Containers without a TOC use PSP11's 4 MiB default. TMR allocations are aligned
to 1 MiB; `SETUP_TMR` carries both GPU and GPU-physical addresses with flags=2.
Readiness requires a successful matching-fence completion. TOC staging is
released only after completion or verified ring destruction; uncertain TMR
installation retains the reservation and prevents retry. `unsafe stop().await`
requires every TMR consumer to be quiescent and destroys TMR before the ring.
Rejected teardown and cancellation retain device-owned memory.

`Psp::new` and the standalone `setup_tmr`/`load_dmub` methods remain Phoenix
operations and reject a Navi22 session. This transport does not enable graphics
and still requires real-card validation and platform boot integration.

### Navi 22 SMC firmware and SMU version handshake

`amdgpu_smu_navi22::Firmware::open(gpu, registry_cap)` reads
`amdgpu/navy_flounder_smc.bin` through live registry/blob capabilities and
keeps an immutable, bounded copy. It requires PCI ID `1002:73df`, GC 10.3.2
and MP1 11.0.11, with unique instance-zero IPs and a complete MP1 register
window. `amdgpu_smc_firmware::Image::parse` accepts SMC header v2.0 / IP 11.0,
checks the declared file size, aligned nonempty microcode range and disjoint
file-relative PowerPlay table range. Limits are 2 MiB per container and 1 MiB
of microcode. It exposes `payload()`, `version()` and optional `powerplay()`;
the SRAM start address is metadata, never a host/GPU DMA address. Structural
validation does not authenticate the image or select board power policy.

`Psp::load_smc_navi22(&Firmware).await` requires a Navi22 ring with acknowledged
TMR setup. It stages only the microcode and submits `LOAD_IP_FW` (6), firmware
type SMU (18), using the GPU address and exact payload length. Matching-fence
completion releases staging; missing completion retains device-owned memory.
SMC loading is attempted once per session: success, failure or cancellation
all prevent another upload. Verified stop/reset is required before a new
session. This is a cold-boot operation before other IP loads, not a firmware
reload, attach, BACO or resume path. PSP completion alone does not prove that
the SMU is responsive.

`unsafe amdgpu_smu_navi22::Smu::after_upload(gpu, pci_cap)` requires exclusive
MP1/reset/power ownership, permanent mappings, successful cold-boot SMC upload
and no outstanding mailbox command. Construction does no MMIO.
`verify().await` sends only `GetDriverIfVersion` (3) and `GetSmuVersion` (2),
using MP1 base index 0: C2PMSG66 message, C2PMSG82 argument and C2PMSG90 response.
The cold-start response may be zero. Each command clears response/argument
before publication and uses timer futures with a 1 s deadline. Every I/O batch
checks current PCI authority. Success returns `Versions { firmware, interface }`
with interface `0x0e` and a nonzero firmware version; all-ones reads, rejection,
timeout, revocation and interface mismatch fail closed. State moves from
`Prepared` to `Querying` to `Ready` or `Failed`; cancellation retains `Querying`
and prohibits replay. The handshake does not program board power, enable
DPM/graphics or set `AmdGpu::fw_loaded`.

### Navi 22 board PowerPlay preparation and upload

`amdgpu_power_navi22::Prepared::new(vbios, smc_firmware, Identity)` builds an
immutable board table without device I/O. `Identity` contains the PCI revision
and subsystem IDs; production reads them under live PCI authority. ATOM master
data revision 2.1 and FirmwareInfo 3.4/3.5 select the source: table ID zero uses
the VBIOS PowerPlay table, while a nonzero ID uses the SMC v2.0 container's
single embedded table. A missing or invalid selected source fails without
fallback. Supported Navy Flounder tables are exactly 2470 bytes, revision
16.0 / format `0x81`, with an 802-byte driver prefix and a 1668-byte SMC
version-1 payload. Other wire layouts are refused.

Preparation overlays the 292 bytes after the ATOM SMC_DPM_INFO 4.9 header onto
the payload's `I2cControllers` through `BoardReserved` region, preserving SKU
data and final SMU padding. The Linux ASUS revision-C3 quirks apply only to
subsystem vendor `1043`, devices `16c2`/`133c`: clamp GFX table entries to
2500 MHz, and set `BoardReserved[0]` to 1387 only for `16c2`. `bytes()` exposes
the immutable SMC payload; `info()` reports source/table ID, platform flags,
thermal-controller metadata, software shutdown temperature and quirk use.
Preparation does not execute ATOM commands or apply user clock overrides.

`unsafe Smu::upload_power_table(&Prepared, &Pool).await` requires the successful
version handshake, a table prepared for this GPU, exclusive trained VRAM/HDP
and index-latch ownership, and completed PSP startup. Before staging, it reads
the bounded PSP runtime database's SCPM entry. Nonzero SCPM policy refuses the
transfer with `PowerPolicy(value)`; malformed policy also fails before any SMU
command or address publication. This path does not delegate table control to
PSP. The uploader verifies the existing HDP flush remap, copies the payload to
an owned CPU-visible VRAM reservation, flushes it, then sends
`SetDriverDramAddrHigh`, `SetDriverDramAddrLow`, and `TransferTableDram2Smu`
for table zero, using the reservation's GPU address. Each command checks live
authority and has a one-second timer deadline.

State moves from `Ready` to `UploadingPowerTable` to `PowerTableReady` or
`Failed`; cancellation retains `UploadingPowerTable`. Success, rejection and
cancellation prevent replay. The owner retains the published allocation even
after acknowledgement because the SMU retains its address; dropping it
quarantines the allocation. Prepublication failures release their reservation.
Table upload alone does not enable DPM features or establish graphics readiness.
`Prepared::boot_policy()` validates that the board enables GFX DPM together
with PPT/TDC limits, firmware critical-temperature protection, automatic fans
and thermal throttling. Production preparation requires these before claiming
hardware. The immutable `BootPolicy` intersects board features with the driver
allowlist; it cannot enable a feature absent from the board table.

`unsafe Smu::configure_power().await` requires the uploaded board table and
confirmed RLC autoload, exclusive ownership and idle queues. It sends `RunDcBtc`,
sets the high/low allowed feature words, enables SMU features, verifies both
running feature words, and reads the board's minimum/maximum GFX DPM frequencies.
Missing required protection, unexpected enabled features or invalid frequency
limits fail closed. `PowerStatus` reports allowed/enabled masks and the observed
MHz range. State is `ConfiguringPower` until `PowerReady` or `Failed`; dropping
the future retains the in-progress state and prevents replay. No failure resets
hardware or releases its transfer buffer.

The boot allowlist includes GFX DPM/prefetch, PPT/TDC, VR0HOT, firmware critical
temperature, fan/thermal control, GFX spread spectrum, out-of-band monitoring
and APCC DFLL when present in the board table. UCLK/FCLK/SOC/display/PCIe DPM,
memory-voltage scaling, deep sleep, GFXOFF, BACO and hub/media gating remain
disabled until their owners supply constraints. This does not install OS
thermal interrupts or override board frequencies, voltages or fan curves.

### Navi 22 graphics firmware and PSP autoload

`amdgpu_gfx_navi22::Firmware::open(gpu, registry_cap)` prepares the complete
`navy_flounder_{sdma,ce,pfp,me,mec,mec2,rlc,vcn,dmcub}.bin` set through live registry/blob
capabilities before any device I/O. Device gating requires PCI `1002:73df`,
GC 10.3.2, MP1 11.0.11, SDMA0 5.2.2 and DCN 3.0.0, with unique instance-zero
records, plus a single VCN 3.0.0/3.0.64/3.0.192 instance. Other media layouts
are refused; VCN 3.0.16 uses different firmware and is not Navy Flounder.
Only MEC2 may be absent, and only a registry `NotFound` result is optional;
signature, parsing, allocation and authority failures propagate. Immutable
copies outlive the capability invocations. `images()` returns validated views
in upload order.

`amdgpu_gfx_firmware::Image::parse(Source, bytes)` supports CP header v1.0 /
IP 10.3, SDMA v1.0 / IP 5.2, RLC v2.2–v2.4 / IP 10.3, and VCN/DMCUB v1.0 /
IP 3.0. Each container is
bounded to 4 MiB and each referenced range to 2 MiB. Declared file/header sizes,
aligned ranges, descriptor bounds and RLC section overlap are checked. This
path rejects incorrect declared sizes rather than using Linux's RLC size
workaround. `source()`, `version()` and `payloads()` expose the selected image;
each payload provides immutable `bytes()` and its PSP `firmware_type()`.
Parsing alone neither authenticates a blob nor permits hardware loading.

SDMA/CE/PFP/ME use the full common-header microcode range. MEC/MEC2 use only
the prefix before the trailing jump table: the table must be nonempty and end
exactly at the microcode boundary. Separate MEC jump-table uploads and repeated
SDMA instance uploads are omitted for PSP11 autoload. RLC arrays use file-relative
byte offsets. Upload order is tap-delay sections (v2.4), restore control/GPM/SRM,
IRAM/DRAM, P/V (v2.3), then RLC_G. Empty optional sections are omitted; register
list metadata is validated but never submitted as firmware. Nonempty P/V fields
in v2.4 are rejected because Linux does not load them in that revision.
VCN submits the complete common-header microcode payload as PSP type 13.
DMCUB submits only `inst_const_bytes` as type 51, retaining PSP packaging and
excluding BSS/data; its instruction/data sizes must exactly cover the payload.
Both media payloads must end at the declared file boundary.

`Psp::load_gfx_navi22(&Firmware).await` requires an acknowledged TMR and successful
SMC upload. It validates the whole set/order before loading any member, sends
bounded/fenced `LOAD_IP_FW` commands through owned VRAM staging, and submits
`AUTOLOAD_RLC` (`0x21`) immediately after RLC_G succeeds, before VCN and DMCUB.
It validates the entire set before publishing any payload. The public
`gfx_load_state()` transitions `Absent → Loading → Accepted | Failed`;
cancellation retains `Loading`. Success, error and cancellation all prevent
replay in that session. Exact fence completion releases staging; incomplete
commands quarantine staging/ring/TMR, and teardown still requires independent
reset of every firmware consumer before TMR destruction.

`Accepted` means PSP acknowledged autoload and both media uploads.
`media_firmware()` returns `MediaFirmware { vcn, dmcub }` GPU entry addresses
from completed PSP replies; each must be dword aligned and inside this
session's retained TMR. Partial failures retain any earlier valid address for
diagnostics. These are not CPU pointers or proof that the media engines have
started. Consumers must keep TMR alive. The API does not configure memory hubs,
queues, VCN/DMUB windows or board power, or set `AmdGpu::fw_loaded`.

`Psp::wait_gfx_boot_navi22().await` requires this session's acknowledged autoload
and checks GC 10.3.2 `CP_STAT` (base index 0, dword `0x0f40`) together with
`RLC_RLCS_BOOTLOAD_STATUS` (base index 1, dword `0x4e8d`). Both banks must fit the
BAR5 mapping at construction. Each paired sample checks live PCI authority;
both registers are read without GC writes. Success requires `CP_STAT == 0`
and `BOOTLOAD_COMPLETE` (bit 31). All-ones reads indicate removal, never success.
The wait uses 1 ms timer futures with a 1 s deadline. State progresses from
`Accepted → Checking → BootComplete | Failed`; cancellation retains `Checking`
and blocks replay. `gfx_boot_status()` retains the last `GfxBootStatus
{ cp_stat, rlc_bootload }` sample for timeout/removal diagnostics. No sample is
produced when authority is already revoked. Waiting never releases ring/TMR
ownership; verified consumer reset remains mandatory for teardown.
`BootComplete` does not initialize queues, enable SDMA or establish acceleration.

### Navi 22 VRAM-only memory hubs

`unsafe amdgpu_gmc_navi22::Gmc::new(gpu, pci_cap, pool)` validates the physical
Navi22 GC 10.3.2, MMHUB 2.1.0 and NBIO register banks and reserves four VRAM
pages without I/O. The caller owns the hubs, VRAM, HDP and reset/PM controls,
excludes all queues and VMs, and retains permanent mappings. Initialization
requires trained VRAM, completed PSP/RLC boot and disabled automatic gating.
`unsafe initialize().await` checks both hubs' framebuffer geometry and that
all 16 contexts are disabled before writing either registers or backing pages.
The HDP flush remap must already match the PSP-installed byte offset `0x7f000`.

The first page holds a flat VMID0 table; only two PTEs are valid, mapping the
owned source/destination pages in a 2 MiB aperture above the framebuffer range.
The second owned page is the fault/default backing. PDEs/PTEs contain GPU
physical VRAM addresses derived from framebuffer base/offset, never PCI BAR
addresses; SYSTEM is clear. System-aperture bounds use 256 KiB units. User
VMIDs, identity mapping, fault IRQs and retry remain disabled. Fault fallback
targets owned VRAM, not system memory. This introduces no host DMA mapping.
Both hubs invalidate all page-table caches for VMID0 using engine 17; MMHUB's
semaphore is acquired first and released only after acknowledgement. Every
sample checks live authority and waits through timer futures with a 100 ms
deadline. Removal, revocation, cancellation and timeout prevent replay and
retain all published memory; no implicit reset or semaphore release is tried.

`state()` reports `Prepared`, `Programming`, `Invalidating(Hub)`, `Ready` or
`Failed`; `aperture()` returns published `Aperture { start, size, source,
destination }` address metadata, including after a started failure. Only
`Ready` confirms both TLB acknowledgements. Keep the owner alive while a
consumer uses these translations; this stage alone does not prove GPU access.

### Navi 22 SDMA0 execution proof

`unsafe amdgpu_sdma_navi22::Sdma::new(gpu, pci_cap, pool)` validates SDMA 5.2.2,
GC 10.3.2, HDP 5.0 and NBIO, then reserves a 4 KiB ring and 4 KiB writeback page
without I/O. SDMA0 registers come from GC base index zero, not the standalone
SDMA discovery bank. The caller exclusively owns this physical GPU and its
permanent mappings, VRAM pool, queues and reset/PM controls.
`unsafe initialize(&mut Gmc).await` requires completed PSP/RLC/SDMA firmware
loading, trained VRAM, disabled power gating and the same GPU's ready GMC.
Preflight checks the framebuffer range, HDP remap, idle SDMA0, no outstanding
GRBM reset and disabled GFX/PAGE/RLC0/RLC1 rings before any writes.

Startup asserts only SDMA0's GRBM reset, waits at least 50 us, releases it and
waits another 50 us using timer futures. It programs a privileged VMID0 direct
ring with byte-addressed pointers, VRAM read-pointer writeback and write-pointer
shadow polling, UTC L1, and the primary driver's cache policy. Doorbells,
indirect buffers, context switching/preemption and interrupt delivery remain
disabled. The single submission writes 16 distinct dwords through GMC's source
virtual address, copies 64 bytes to its destination, emits an uncached fence
at the destination page's end, and pads to 16 dwords. HDP flush precedes the
write-pointer kick; HDP read-cache invalidation precedes CPU observations.
Success requires the fence, both MMIO and VRAM read pointers at 128 bytes, and
an exact comparison of all source/destination words. No host DMA is introduced.

`state()` reports `Prepared`, `ResetAsserted`, `ResetReleased`, `Programming`,
`Submitted`, `Verified` or `Failed`. `proof()` retains `Proof { copied_bytes,
fence, read_pointer }` only after full success. Each I/O batch checks current
authority; completion has a 1 s deadline. Revocation, cancellation, removal,
timeout or corrupted data prevents replay. Ring/writeback memory is published
before reset and retained on every started path; no destructor resets hardware.
This is one boot execution test, not a general submission or acceleration API.

### Navi 22 kernel queues: GFX, KIQ/compute and SDMA

GC 10.3.2 runs without MES. `amdgpu_cp_navi22::Doorbells::map_navi22(device)`
(unsafe, boot-time) maps BAR2's first 4 KiB uncached; kernel doorbells use the
Linux Navi10 assignment (KIQ 0, MEC ring0 6, GFX ring0 0x116, SDMA0 0x200,
SDMA1 0x214 dwords). `enable_doorbell_apertures` sets the NBIF 2.3 doorbell
and self-ring apertures. Each queue owns 24 KiB of published VRAM: 8 KiB ring,
writeback (rptr, 64-bit shadow wptr, fence, scratch), IB, MQD/CSB and EOP.
Commit pads like `amdgpu_ring_commit` (256 PM4 / 16 SDMA dwords), flushes HDP,
updates the shadow wptr and rings a 64-bit doorbell; CPU reads invalidate HDP.

`unsafe Gfx::new(gpu, pci_cap, pool, doorbells)` reserves storage only.
`configure()` applies `golden_settings_gc_10_3_2`, checks/programs the GRBM
CAM, runs `gfx_v10_0_constants_init` (SH_MEM per VMID, KFD/GDS VMIDs, trap
config), re-checks RLC autoload, programs the RLC CSIB with the 949-dword
`clearstate_gfx10.h` CSB, SPM VMID 0xf and SRM, and masks the gui-idle
interrupts. `start()` follows `gfx_v10_0_cp_gfx_resume`/`cp_gfx_start` (the
`async_gfx_ring=0` path, ring 0 only) and then the SCRATCH_REG0
`SET_UCONFIG_REG` ring test. `test_ib()` runs a WRITE_DATA IB and RELEASE_MEM
fence. `unsafe amdgpu_kiq_navi22::Compute::new(...)`: `init_kiq()` programs
the KIQ at MEC2 pipe 1 queue 0 (`kiq_setting`, v10 MQD, `kiq_init_register`,
dequeuing an active inherited HQD or failing on timeout); `map_compute()`
unhalts MEC, builds the MEC1 pipe 0 queue 0 MQD and submits SET_RESOURCES +
MAP_QUEUES through the KIQ, then runs KIQ and compute ring tests; `test_ib()`
runs the compute IB test. `unsafe amdgpu_sdma_navi22_queues::Sdma::new(...)`:
`start()` refuses busy engines, stops an idle predecessor ring (the SDMA0
proof), soft-resets both engines and follows `sdma_v5_2_start` /
`gfx_resume_instance` with doorbells and NBIF SDMA ranges plus WRITE_LINEAR
ring tests; `test_ib()` runs IB + FENCE/TRAP tests on both engines.

Every step has one predecessor state; failure or cancellation leaves a
non-repeatable state and retains published memory. Register polls are bounded
by 100 ms and fences by 1 s. `amdgpu_fence_navi22::{notify, notify_all}` are
the IH hook: an EOP/trap consumer calls them so fence waits re-sample at once;
without it waits poll every 1 ms. `QueueProof` aggregates the three proofs.
Clock gating, GFXOFF, the cleaner shader and Linux's second gfx ring are not
enabled. These are kernel bring-up rings, not a submission API.

### Navi 22 DCN3.0 DMUB startup

`amdgpu_dmub_navi22::Prepared::new(image, vbios, psp_version)` parses the
combined Navy Flounder DMCUB image and stages ordinary RAM before device I/O.
`Image::prepare_dcn30` requires IP 3.0, cached-inbox firmware newer than 1.10.0,
and no separate BSS/shared-state mapping. It uses the existing bounded layout
builder; legacy/unsupported layouts fail before any hardware operation.
`unsafe Dmub::new(gpu, pci_cap, pool, prepared)` bounds DCN3.0 base index 2,
NBIO and HDP 5.0.x, then reserves owned VRAM. It requires exclusive physical-GPU ownership,
permanent mappings, and firmware/VBIOS belonging to this board.

`quiesce().await` checks the DMUB enable fuse, requests `STOP_FW` when inherited
firmware runs, and requires both matching GPINT acknowledgement and stop reply
within 100 ms. Timeout leaves the attempt failed without forced recovery.
It holds DCN3.0 `DMCUB_CNTL.SOFT_RESET` (bit 17) and `MMHUBBUB_SOFT_RESET`
(dword `0x341`, bit 8), disables execution, and clears mailbox pointers/status.
It never uses DCN31's separate CNTL2 reset or dword `0x342` hub reset.

After PSP loads DMCUB, `unsafe start(&Psp).await` validates that execution is
still reset, security reset is released, and both PSP instruction/stack windows
are enabled and wholly inside the retained TMR after GPU-physical translation.
Those secure registers are preserved verbatim. The caller retains the matching
PSP/TMR for DMUB's lifetime, with trained VRAM, ready memory hubs and protected
power. Nonsecure VBIOS/mailbox/trace/state windows use owned GPU VRAM addresses.
The uploaded backing is flushed before publication; mailbox rings are 8 KiB
each. Startup skips panel power sequencing, requires a fresh DAL/mailbox-ready
status within 1 s, then proves the runtime transport before returning success.
It requires `GET_FW_VERSION` GPINT acknowledgement within 100 ms and a version
matching the prepared image metadata. It sends `QUERY_FEATURE_CAPS` through
inbox1 and reports `Status { firmware_version, boot_status, inbox, outbox,
capabilities: Option<FeatureCaps> }`. `FeatureCaps` retains the packed 14-byte
Linux ABI without enabling any advertised feature. As in Linux's
`dc_dmub_srv_query_caps_cmd`, firmware must clear the request's `ret_status`
bit to acknowledge this query; an unchanged bit leaves capabilities absent.
This does not initialize a native mode.

Every I/O batch checks live authority. State is `Prepared`, `Stopping`, `Reset`,
`Starting`, `Running` or `Failed`. Cancellation preserves the in-progress state
and prevents replay. Published storage stays quarantined on failure/drop;
unpublished storage can return to its pool. No destructor changes hardware.

`Dmub::hpd(instance).await` queries a native DCN30 AUX/HPD instance (0..6),
not a connector index. `aux(instance, action, address, data).await` supports
native AUX and I2C-over-AUX with at most 16 bytes, 20-bit addresses, and the
actions defined by `dmub_cmd.h`. AUX enables outbox1 notifications on first
use; there is no automatic NACK/DEFER retry. These methods do not perform link
training, infer board routing or expose arbitrary firmware commands.
`poll_notification()` returns at most one validated raw 64-byte outbox slot.
Up to 16 unrelated notifications are retained while awaiting AUX; overflow
fails explicitly. A stale or wrong-instance AUX reply fails the transport,
because this ABI has no usable request ID for disambiguating late replies.

The owner uses two fixed 8-KiB rings inside its retained reservation. Before
each command it verifies CW4, ring bases/sizes, shadow pointers, firmware-ready
state and HDP remapping. Pointers are byte offsets aligned to 64 within the
ring. One command is outstanding; only its exact read-pointer advance completes
it. CPU writes are flushed through HDP before publishing the inbox write
pointer; firmware replies are read only after HDP read-cache invalidation.
All MMIO and VRAM batches invoke the live PCI capability. Replies must retain
their type/subtype and payload size and cannot assert batched/register commands
or reserved header bits. Inbox and AUX completion each have a 200-ms bound.

`mailbox_state()` is `Dormant`, `Ready`, `InFlight` or `Failed`. Dropping an
operation retains `InFlight` outside the future and blocks replay. Protocol
errors, timeouts, removal, revocation and notification overflow leave `Failed`;
fully consumed AUX NACK/DEFER or firmware rejection returns an error while
leaving the transport ready. Caller validation errors perform no I/O. No
failure resets the device or reclaims published storage. The lifecycle state
and immutable boot report do not replace this live transport diagnostic.

### Coordinated Navi 22 firmware bring-up

The shared `Otg`, `Hubp`, `Dpp`, `Mpc`, `Opp`, `Stream` and `Dccg` constructors
also resolve an exact Navi22/DCN 3.0.0 profile, with six pipes/stream encoders.
Other DCN revisions remain unsupported unless already covered by the Phoenix
profile. Discovery must identify a unique DCN instance and each selected bank
must include the last register of all supported instances; no I/O occurs during
construction. Clock-rate and mode-math ownership remain separate prerequisites.

Navi22 OTG uses its shifted clock/global-sync registers, VTG base `0x0528`,
ODM segment selectors starting at bit 8, and DCN20's disable-point code 3.
Disable follows `optc1_disable_crtc`, preserving ODM routing while retiring the
generator. HUBP's detile-plane field is bits 0..11 and preserves the adjacent
pack-control bit. DCN30 stream unblank resets `DIG_FE_CNTL.DIG_START` before
the steering FIFO, and preserves the pixel-format bit that exists only on
DCN314. DPP/OPP/MPC ids, strides and used fields match the two Linux headers.
DCCG supports all six DPP DTOs and the shared DENTIST divider read/resync;
Phoenix-only pixel-rate and DPIA mux methods return `Unsupported` before I/O
on Navi22. These blocks do not by themselves establish a native display mode.

`amdgpu_dcn30_clk::ClockManager` owns Navi22's separate DAL mailbox and DCCG.
Its unsafe constructor requires the same exclusive physical GPU ownership as
the retained SMU passed to `start`. Before enabling display DPM, it verifies
that all six OTGs and DP streams have retired. SMU then extends its board-bounded
boot policy with UCLK/FCLK/SOCCLK/DCEFCLK and supported memory rail scaling;
autonomous thermal/power/fan protection remains required. Deep sleep, link DPM,
BACO and gating remain excluded. Both owners retain in-flight state across
cancellation and reject replay after incomplete or failed transitions.

`start(smu)` reads the CLK02 PLL at dword `0x17010` and scalar DAL clock levels
(including fine-grained min/max endpoints). It requires message-header version
1 and records the driver-table version without assuming Sienna's table layout.
`Levels::plan` rounds DISP/DPP requests to DENTIST frequencies within board
limits; `ceiling` supplies their highest representable rates. `prepare(plan)`
requires every stream idle, pins memory/fabric/SOC at their upper board states,
sets the display count and DCF/PIX/DISP floors, checks firmware responses, then
waits for DISP and DPP divider completion. No running stream changes clocks.
`pipe_clock` programs a DTO only after successful preparation. No default PLL,
clock table, voltage or memory bandwidth is invented. A failed modeset leaves
floors retained. GDDR6 mode math and the full native pipeline remain separate.

`amdgpu_navi22_boot::Firmware::open(gpu, registry_cap)` validates every required
register bank and prepares the SOS, SMC and SDMA/CP/RLC firmware sets before any
device operation. Missing required firmware or an invalid layout prevents the
entire sequence from starting. `unsafe ColdBoot::new(gpu, pci_cap, pool, firmware)`
requires exclusive ownership of the physical GPU, its PSP/MP1/GC/HDP and reset/PM
controls, permanently mapped and already trained VRAM, no active queues, and an
owned pool excluding all firmware/scanout/discovery/training/TMR reservations.
Firmware and any prepared power table must belong to this GPU's board; exclusive
ownership includes its VRAM index latch.
Construction reserves bootstrap staging but performs no MMIO. This is one
cold-boot attempt, not an attach, resume or firmware-reload operation.
The session owns an immutable copy of its register/identity metadata, so it
does not borrow `AmdGpu` or require a controller guard across any await. Both
constructors return a `Send + 'static` owner which may leave `with_controller`
before `run` is polled. This copies no physical ownership: callers must still
exclude reset/PM/other clients and retain permanent mappings for the session.

`ColdBoot::run().await` executes optional memory training → SOS bootstrap →
ring creation → trusted-memory setup → SMC upload → SMU version handshake →
optional board PowerPlay upload → optional DMUB quiesce → graphics upload/autoload → RLC boot check →
optional board calibration/protected GFX DPM setup → optional memory hubs →
optional SDMA execution test → optional DMUB start.
Production cold boot emits a serial `start` and terminal `complete` or
`failed` checkpoint for each stage. A pending/cancelled stage emits no false
completion; checkpoints do not run per poll or write training-owned framebuffer
memory. These markers identify startup progress, not native-display readiness.
`ColdBoot::prepare_memory_hubs()` reserves the above VMID0 backing before run;
it requires a prepared board power policy and performs no I/O. Production boot
always calls it. Explicit firmware-only callers may omit this stage.
`ColdBoot::prepare_sdma()` reserves the SDMA ring/writeback before run and
requires prepared memory hubs. Production boot also calls it. `Stage::SdmaTest`
identifies a failure in this stage, with the SDMA error retained.
`Firmware::prepare_dmub(gpu)` prepares board-specific DMUB backing before
construction; `ColdBoot::prepare_dmub()` reserves its VRAM after memory hubs
are prepared. Production boot requires both calls. This places `DmubQuiesce`
before any PSP DMCUB upload and `DmubStart` after memory-hub/SDMA startup.
`DmubStart` includes the runtime version/capability handshake above.
`ColdBoot::prepare_queues(doorbells)` reserves the GFX, KIQ/compute and both
SDMA queue owners after memory hubs and the SDMA proof; production boot calls it
when BAR2 maps. After `DmubStart` the stages `Doorbells`, `GfxSetup`, `Kiq`,
`ComputeQueues`, `GfxRing`, `SdmaQueues` and `IbTests` follow Linux's
`nv_common_hw_init`, `gfx_v10_0_hw_init`/`cp_resume`, `sdma_v5_2_start` and
`amdgpu_ib_ring_tests` order; `Report::queues` is set only when all pass and
failures are reported as `Error::Queues`.
`Firmware::prepare_power(gpu, Identity)` prepares the board table before the
session is constructed; production boot requires it, while explicit
firmware-only callers may omit it. The bootstrap owner is dropped only
after SOS success, before claiming
the GPCOM ring. The ring and SMU owners are stored in the session before awaiting
their hardware operations. State is `Prepared`, `Running(Stage)`,
`FirmwareReady(Report)`, `Failed { stage, error }`, or `Released`. Failure records
the exact stage and underlying error; cancellation preserves `Running(stage)`.
Every attempt prevents replay, and no failure automatically resets hardware or
destroys device-owned memory. Dropping a session quarantines any memory still
owned by hardware through the underlying owners' existing rules.

Success returns `Report { smu: Versions, gfx: GfxBootStatus, power: Option<Info>,
power_status: Option<PowerStatus>, media_firmware: MediaFirmware,
memory_aperture: Option<Aperture>, sdma: Option<Proof>, dmub: Option<Status> }`;
`power` is populated only when the prepared table was uploaded. The session must
stay alive, or `take_psp()` can transfer its live ring/TMR owner to subsequent
GPU initialization after full success; that changes state to `Released` and
prevents a second transfer/run. `gfx_boot_status()` exposes the retained last
GC sample before transfer, including on failure. These observations do not set
`AmdGpu::fw_loaded`. Display-aware memory/link DPM, OS thermal interrupts,
general GPU mappings/queues, VCN startup and real-card validation remain
separate work.

`ColdBoot::dmub_hpd`, `dmub_aux` and `dmub_notification` expose the typed runtime
operations only after `FirmwareReady` and while PSP/TMR remains retained.
They refuse access after `take_psp()`. `dmub_mailbox_state()` also reports failed
or cancelled transport attempts without accessing hardware.

### Navi 22 boot ownership and framebuffer handoff

`amdgpu_navi22_platform::prepare(physical_boot_framebuffer)` is an unsafe,
single-CPU boot-only entry. It requires a posted physical GPU, permanent probe
mappings, no NARF VRAM allocations/queues, and stopped CPU framebuffer writers.
It reads the PCI board identity and validates every required firmware file and
the prepared board PowerPlay table before reading the live VRAM plan,
constructs the exclusive pool and optional training owner, and retains the
complete `ColdBoot` in a static async mutex. A GOP range wholly outside this
GPU's aperture denotes a secondary GPU; partial overlap, overflow and invalid
geometry are refused. Preparation errors issue no device writes and preserve
controller access. When training is requested, live firmware/DMUB reservations
in the overwritten 32 MiB prefix also refuse startup; allocator exclusions
alone cannot protect them. Inventoried display/cursor readers may remain live
and can show transient training pixels. Success permanently claims MMIO ownership before releasing
the controller spinlock. `with_controller` and `with_controller_mut` then
return `None`; DRM identity/memory queries use a separate immutable snapshot.

`unsafe amdgpu_navi22_platform::run().await` requires CPU writers stopped and
runs the retained session once. The owner survives return or cancellation;
there is no automatic retry, release or reset. `status()` returns `Absent`,
`Running` while locked, or `Retained(Diagnostics)` with the session state,
training state, last raw GC boot-status sample and DMUB mailbox state. Failure identifies its exact
stage and underlying error. Firmware readiness never advertises acceleration or a native mode.
`dmub_hpd(instance).await`, `dmub_aux(instance, action, address, data).await`
and `dmub_notification().await` serialize runtime access through the same async
owner mutex; no controller spinlock or escaping DMUB/PSP owner is needed.
Navi22 is excluded from the DCN314 USB-C startup path. Its suspend handler
returns `NotImplemented` before changing PM state or issuing commands; discrete
GPUs cannot resolve the legacy APU SMU mailbox through `mp1_mailbox_base`.

`narf-fb` registers `amdgpu-navi22-firmware` during Subsys, appending it after
the statically registered Late firmware scans and framebuffer initialization.
This synchronous boot call runs before executor polling and userspace mmap.
It pauses cached writers, scanout/fbdev discovery, drain/cursor/status pumps,
and takes the early console under its lock to drain its current writer.
`block_on_spin` then polls the timer/self-waking firmware future with no IRQ
spinlock held. Preparation failure resumes the console. After a started run,
success restores access; failure on the primary GPU leaves framebuffer access
quarantined and serial logging available. Failure on a secondary GPU restores
the unrelated boot framebuffer. This is **not** a runtime pause mechanism and
does not revoke existing userspace mappings. Training resume/reset support is
required before exposing such a mechanism.

`unsafe ColdBoot::new_with_training(..., exchange)` additionally owns a
`amdgpu_gddr6::Trainer` and runs it before constructing the SOS owner. Exchange
offsets come from `Plan::training()`. It inherits `ColdBoot::new`'s contracts
except that final GDDR6 training is performed by this session, and requires
all CPU framebuffer writers/pumps and other VRAM clients stopped throughout.
Firmware must provide initially readable VRAM for the preimage. Training
failure prevents all firmware uploads. `training_state()` and `training_data()`
expose its progress and successful cache without replaying a command.

`unsafe amdgpu_gddr6::Trainer::new(gpu, pci_cap, exchange)` validates Navi22's
PSP11/NBIO/HDP5 layout, exchange bounds and at least 32 MiB of visible VRAM,
and allocates a 32 MiB system-memory preimage plus a 4 KiB result cache before
I/O. `run().await` skips training for a nonzero resident SOS heartbeat or a
PSP runtime boot configuration that disables two-stage training. The runtime
DB v1.0 window is bounded to 64 KiB, 1 MiB below VRAM end; unknown versions,
duplicate boot entries and malformed ranges fail closed. An absent DB or boot
entry preserves Linux's enabled default. Otherwise it waits for bootloader
readiness, verifies HDP remapping, copies the VRAM
prefix in 4 KiB cooperative chunks, sends long training (`0x100000`) with the
VRAM-relative C2P MiB address, and waits up to three seconds using scheduler
timers. Only terminal completion permits restoring the prefix and flushing HDP.
A terminal rejection still restores the prefix before returning its error;
timeout, removal or revocation never races a potentially active PSP writer.
Successful completion copies P2C through bounded direct/indexed VRAM access
and requires its BIST signature. `training_data()` is available only in `Ready`.

Training state is `Prepared`, `Saving`, `Training`, `Restoring`, `SavingResult`,
`Ready`, `ResidentSos`, `Disabled` or `Failed`. Any started run prevents replay. Cancellation
retains the active state, preimage and cache outside the future. After failure
or cancellation the owner must remain retained and VRAM clients stopped until
independent reset/recovery; drop never restores VRAM or resets the GPU. No
short-training/resume command is exposed yet. The boot-only framebuffer handoff
above supplies the initial CPU-writer exclusion.

### AMD platform VBIOS

`atombios::header::parse_rom_header` and `amdgpu_atombios::Atombios::parse`
share the actual PCI/ATOM layout: 55 AA ROM signature, a u16 header pointer at
0x48, common header followed by ATOM/MOTA at +4, and u16 command/data directory
pointers at +0x1e/+0x20. The declared header and directory sizes must fit the
image; directories contain whole u16 entries. Data tables require at least a
four-byte common header, command tables at least six bytes. Optional zero
directory entries denote absent tables. Parsing does not execute BIOS code.

`amdgpu_vbios::Vbios::from_vfct(table, device)` validates the ACPI checksum,
declared table/image bounds and ATOM directories, then copies exactly one
matching image into immutable storage. Tables are capped at 2 MiB and VBIOS
images at 256 KiB. The match requires segment zero, exact bus/device/function
and vendor/device IDs; specified subsystem IDs must also match. VFCT has no
segment field. Nonzero segments, bus-renumbering guesses and ambiguous matches
are rejected. The Lib1 offset bounds the VBIOS sequence when present.
`bytes()`, `source()` and `version()` expose data already read. These checks
validate structure and identity, not cryptographic authenticity.

GPU probe retains this snapshot in `AmdGpu::vbios`. If VFCT has no image,
Renoir/Phoenix APUs may use the firmware shadow in the first 256 KiB of the
mapped framebuffer BAR, requiring a matching PCIR vendor/device record.
Navi22 uses a bounded SMUIO11 ROM-register fallback and retains the complete
declared ATOM image as `Source::RomRegisters`. Discovery must identify
1002:73df / GC10.3.2, NBIO v2.3-compatible hardware (zero ROM offset), and a
supported SMUIO11 register window. ROM_INDEX/ROM_DATA use base index zero.
Each capability-checked read chunk saves/restores ROM_INDEX and reads at most
4 KiB through ROM_DATA's dword autoincrement. The ROM/AMD signatures, nonzero
512-byte-block image length, matching PCIR identity and all ATOM directories
must validate; the full image's header must agree with the initial snapshot.
Probe reports the retained source/size or acquisition error. Navi22 no longer
uses the old ROM-BAR version-only fallback. No PCI ROM decoding, flash writes,
reset or ATOM execution is performed by this read path.
Malformed or ambiguous VFCT data does not trigger fallback. Reads use live
PCI authority through `Cap::invoke`; shadow reads recheck it per 4 KiB.
The new path never enables an expansion ROM or writes VRAM. Failed discovery
leaves VBIOS unavailable without preventing the existing display attachment.
Discrete GPUs retain their older ROM-version fallback, which does not supply
loader data. Boot ACPI tables and GPU mappings must remain readable during
the probe's unsafe acquisition operation.

### AMD DCN 3.1.4 USB-C display transport

`amdgpu_dmub::Firmware::open(&AmdGpu, &Cap<FirmwareRegistry, Read>)`
selects `amdgpu/dcn_3_1_4_dmcub.bin` from exact DCN IP discovery, rejecting
missing, duplicate or unsupported DCN instances. It does not use the coarse
PCI family's firmware list. The firmware registry owns authentication.
Registry lookup and copying the bounded image use `Cap::invoke`; the returned
object owns an immutable copy, so no registry memory borrow survives the read.
It contains data already read, not authority to replace running firmware.

`amdgpu_dmub_firmware::Image::parse` validates the v1.0 container bounds,
splits the PSP-signed payload from the executable and BSS/data, and locates
legacy or combined DAL metadata with 256/512-byte PSP footers. It rejects
missing metadata and unbounded state/trace sizes. The header CRC field is
not treated as authentication. `Firmware::prepare(vbios)` produces the
DCN314 seven-window layout with 256-byte region starts, 64-byte sizes and
4096-byte total alignment. Separate BSS/shared-state mappings remain
unsupported for this hardware path. The caller supplies a compatible,
validated VBIOS; preparation checks its storage size, not ATOM semantics.
`Firmware::prepare_from_gpu(&AmdGpu)` instead uses the retained, validated
platform snapshot, rejecting missing VBIOS or unsupported DCN discovery.

`Prepared::stage` initializes an ordinary RAM buffer, copying executable and
VBIOS data and zeroing padding, stack, mailboxes, trace and state. It rejects
a short buffer before writing anything. `Layout::place` checks page alignment,
48-bit GPU addresses and aperture bounds; it computes addresses without
allocating VRAM or proving exclusive ownership. These preparation APIs perform
no MMIO and do not mark firmware as loaded.

`amdgpu_vram::Pool::from_owned_range` is unsafe: its caller must provide a
permanent CPU mapping of GPU VRAM exclusively reserved for the pool, excluding
BIOS, scanouts, PSP/TMR, discovery tables and other clients. The allocator
does not discover free memory from BAR capacity. Page-aligned reservations
remain unavailable while allocated, and hardware-published reservations are
quarantined on drop unless their engine has verified shutdown.
`Pool::reserve_aligned` additionally takes a power-of-two GPU-address
alignment of at least one page, for the 1 MiB-aligned PSP TMR; its padding
stays available to other allocations.
`Pool::from_owned_aperture(mapping, gpu_base, protected)` additionally retains
permanent aperture-relative exclusions. Ranges are checked, rounded outward
to pages, sorted and merged; dropping an allocation never removes a protected
range. The same unsafe ownership contract applies to the remaining memory.

`amdgpu_vram_boot::Plan::read` snapshots the DCN314 FB base/top/offset through
live PCI authority and builds a read-only VRAM inventory. It requires the
bootloader framebuffer's bus-physical byte range and explicit GPU-address
ranges for other clients. It retains the entire framebuffer prefix (at least
Linux's 9 MiB VGA reservation), the VBIOS FirmwareInfo v3.4/v3.5 tail, the
discovery tail, VRAMUsage v2.1/v2.2 firmware/driver ranges, and existing
supported DMCUB windows. FirmwareInfo and the master directory revision must
be known; missing or unsupported metadata, SR-IOV reservation modes, invalid
translations and all-ones register reads fail closed. Unsupported active
CW2/CW7 and Region4/6 layouts also reject provisioning. CW0/1 addresses use
the inverse MC translation; other supported windows use GPU addresses.

The plan preserves full-aperture offsets even when BAR0 is smaller than VRAM.
`Plan::into_pool` clips exclusions to the visible mapping before allocation.
It is unsafe: the caller must have included all other scanouts, cursors,
PSP/GART buffers and existing pools, own the unprotected memory, and serialize
future GPU reconfiguration. An inventory alone is not ownership authority.
No hardware is modified while gathering reservations or creating the pool.

`unsafe Plan::read_navi22(gpu, pci_cap, boot_framebuffer, other_clients)`
provides the equivalent inventory for physical 1002:73df / GC10.3.2 / DCN3.0.0.
It reads GMC10 base/top/offset, verifies that the full aperture matches the
probe's physical VRAM size and that DCN's address translation agrees, and
retains the same firmware, boot and DMUB exclusions. An optional boot framebuffer
permits a secondary/headless GPU. All six DCN3.0 pipes' programmed and latched
linear RGB scanouts and supported cursors are inventoried automatically using
their own register window. Unknown/tiled/DCC/VM surfaces fail closed. All sixteen
GC10.3.2 and MMHUB2.1.0 VM contexts must be disabled; a live context, initialized
firmware or programmed NARF mode returns `Busy`. Additional clients still
require explicit GPU-address ranges. Unhandled enabled DMUB Region0/1/2/7 also
reject provisioning.
The PSP runtime database (64 KiB at VRAM-end minus 1 MiB) remains reserved even
if FirmwareInfo reports a smaller firmware tail or disables two-stage training.
FirmwareInfo's two-stage BIST capability additionally reserves a 4 KiB C2P
exchange at `ALIGN(vram_size - firmware_tail_size - 1 MiB, 1 MiB)` and a 4 KiB
P2C exchange 32 KiB below physical VRAM end. C2P must not overlap any client or
firmware reservation. `Plan::training()` reports these VRAM-relative offsets;
it does not attest completed training or authorize a training command. Exclusions
remain correct with a small BAR0 or Resizable BAR exposing all 12 GiB.

`amdgpu_dmub_boot::Loader::new` validates exact DCN314 discovery, the PCI
capability, register bounds and the pool's CPU/GPU address correspondence,
reserves its image storage, and claims exclusive DMUB/PM ownership. Its unsafe
contract requires the matching authenticated image, validated GPU-specific
VBIOS, persistent mappings and a platform supporting direct loading.
`boot(options).await` implements Linux's explicit direct-load path: bounded
STOP_FW/reset, volatile VRAM upload with complete WC readback, translated MC
addresses for CW0/1, GPU addresses for CW3..6, window/mailbox readback checks,
boot options, reset release and DAL/mailbox readiness. It is not a fallback
for a failed PSP load. Uploads yield after each 4 KiB; all waits use scheduler
futures. Only a completed boot exposes HPD/AUX/Type-C commands, whose every
future poll revalidates PCI authority through `Cap::invoke`.

`Loader::from_boot_memory` combines the retained VBIOS, the reservation plan
and allocator with the same direct-load lifecycle. It requires a complete
boot/client inventory under exclusive ownership and does not reset or upload
until `boot` is explicitly awaited. The reservation retains its pool for the
loader's lifetime, including failed-stop quarantine. This constructor does
not supply the platform boot inventory or enable automatic firmware loading.

`amdgpu_psp_ring::Psp::new` is unsafe: it claims the sole Phoenix PSP 13.0.4
GPCOM ring, its HDP remap hole and the exclusive right to replace the TMR, and
reserves its ring/fence buffer from the caller's pool. `start().await` requires
live SOS firmware, verifies the HDP remap before publishing any device memory,
zeroes and flushes the ring, then creates it with Linux's register sequence and
handshake delay. `setup_tmr(toc)` and `load_dmub(signed_instructions)` submit
bounded GPCOM commands; every address on the ring is a GPU address, never a host
physical address. Replies are validated, a stale fence never completes a command,
and a rejection surfaces the firmware status rather than a generic failure.
Commands are capped at 16 MiB. `bank` resolves an exact IP-discovery register
bank and is the only supported way to address one. The ring authenticates
nothing itself: the registry owns container authenticity and the PSP owns
signature verification. Dropping without verified shutdown quarantines every
published buffer, payloads included.

`Loader::new_psp` selects the PSP load method instead of the direct one, keeping
the device, mapping and pool contract of `new` and adding exclusive PSP, HDP and
power-management ownership. It validates the TOC container and retains its own
copies of the signed instruction payload and TOC, so no registry borrow
survives construction. `boot` then starts the ring, installs the TMR and loads
DMCUB through the PSP, and the secure instruction and stack windows stay owned
by the PSP: they are verified as enabled rather than programmed, and are never
cleared by mailbox teardown. A failed PSP load does not fall back to direct
load, and a dropped boot future cannot start a second attempt. Phoenix now
rejects the legacy and multi-firmware PSP load helpers outright, so no other
path can race this ring.

`amdgpu_platform` assembles the one platform display owner. `fb`'s generic
registration records the physical boot framebuffer geometry before fbdev
replaces its address with a virtual mapping; recording performs no GPU access.
`prepare` refuses to guess: it rejects a GPU with loaded firmware or a live
mode, rejects any live VM context rather than sizing inherited page tables, and
inventories every enabled HUBP surface and cursor — including latched and
earliest-in-use addresses, since a boot-time flip can still be draining its
previous allocation. Only packed linear RGB is treated as a bounded inherited
scanout; DCC, YUV, stereo, VM and all-ones reads reject provisioning instead of
overlooking metadata. The resulting inventory feeds the reservation plan, pool
and PSP loader. Failure leaves the pre-existing firmware attachment usable.
The Late worker takes this owned path when it succeeds and otherwise attaches to
running firmware. A partial boot retains ownership and the busy phase so no
attach fallback can race an outstanding PSP command; suspend stops the loader
and a failed resume now propagates a device-PM error instead of continuing.

`stop().await` stops owned hardware even after capability revocation. A
cancelled/failed boot cannot be retried until stopped. Dropping the loader
attempts a bounded synchronous reset without waiting; if stop cannot be
verified, VRAM and global mailbox/PM ownership remain quarantined. Suspend
is refused for the loader's lifetime pending firmware replay support. A
suspended GPU also rejects new loader claims and generic firmware replacement.
The stream pipeline that a booted loader would drive remains open.

`amdgpu_dmub::Dmub::attach(&AmdGpu)` is unsafe: the caller must retain exclusive
mailbox and GPU power/firmware ownership for its lifetime. It requires exact
DCN 3.1.4 IP discovery, running DAL firmware and bounded VRAM inbox/outbox
windows. Async HPD, Type-C PHY state and AUX commands serialize mailbox access,
validate replies, and poison the channel after timeout or cancellation.

`amdgpu_usbc::sinks()` returns detected native-AUX/DPIA sinks with DPCD and
checksum-validated EDID (base plus up to four extension blocks). The Late-stage
worker is the sole mailbox owner, responds to UCSI changes, and periodically
rescans without assuming a UCSI-to-GPU wiring map. Suspend is refused while a
command cycle is active; resume revalidates the firmware mailbox mapping.
Firmware replacement is rejected while this worker owns DMUB.

`amdgpu_dp_training::train` performs async 8b/10b clock recovery and channel
equalization over a caller-supplied `LinkIo`, which owns the AUX channel and
source encoder for the whole operation. Source and sink are programmed as one
transaction: AUX success alone never proves a trained link. Only rate/lane
combinations that can carry the requested uncompressed mode are attempted, and
each failed attempt clears the sink pattern and disables the source before
falling back to a lower rate. Malformed replies and transport errors abort
instead of masquerading as fallback; loss of interlane alignment fails
equalization. Native links apply a common PHY drive level satisfying the
highest per-lane request, clamped to swing+pre-emphasis <= 3, and stop on
max-swing or five unchanged requests. A transparent USB4 DPIA trains its own
remote PHY: the host writes sink patterns and reads status without applying
native voltage settings. DSC, FEC and MST are not negotiated by this SST path.
Cancelling a training future requires disabling the source before reusing its
scanout memory or training again.

`amdgpu_dio::Source::new` is unsafe: the caller must exclusively own the idle
frontend/backend and its physical route across hotplug, power transitions and
modesets, and the `Route` must come from this GPU's VBIOS or the DPIA
allocator, never a UCSI connector number. Routes are range-checked against the
four DPIA and six native AUX instances, and every register access is offset by
the owned backend and revalidates PCI authority through `Cap::invoke`. Updates
verify their read-back and treat an all-ones read as a vanished device.
`train` drives the training state machine through a booted loader's `Phy`
commands: a native Type-C transmitter's reported pin assignment clamps the lane
count, a disabled Type-C PHY is refused before anything is programmed, and a
trained source must be explicitly disabled before it can train again. Only a
sink-side AUX DEFER or timeout is retried, so a poisoned mailbox never looks
like a NACK. `disable` detaches the stream frontend only once the PHY is
confirmed off; a caller must also stop the timing generator and HUBP before
releasing scanout memory.

`amdgpu_dcn_clk::ClockManager::new` is unsafe: it claims the DCN314 display
clock mailbox, which is a distinct interface from the GFX SMU's even though
both live on MP1 — C2PMSG_67/83/91 against the power driver's 66/82/90, and
the VBIOSSMC message set rather than PPSMC. Holding it grants no
power-management authority, so the caller must also keep the GFX driver off
those registers. `start().await` proves the mailbox answers, then publishes a
pool reservation to firmware and reads back the DPM table; the buffer is zeroed
first so firmware that writes nothing cannot pass as a valid table. Level
counts outside 1..8, clock values outside Linux's 1 < MHz < 100000 range and
missing DF p-states all fail closed, and no clock can be requested until the
table is latched. `update(requested, safe_to_lower, consumers)` applies Linux's
order: DTBCLK before the clocks that need it, the DCFCLK floor and deep-sleep
floor, DISPCLK, then the global DPPCLK and its per-DPP dividers — dividers
first when the global clock drops, so no pipe is ever fed a clock above what
its divider was programmed for. Requests above the firmware's own DPM ceiling
are refused rather than clamped, DPPCLK keeps Linux's 100 MHz floor, and a BIOS
that left DCFCLK DPM disabled refuses the two floor messages without aborting
the modeset, since the boot clock already satisfies the request. The DCCG
dividers and the DMCUB clock notification are supplied by the caller through
`Consumers`, because neither the DCCG bank nor the firmware mailbox belongs to
this module. DPREFCLK and DTBCLK are the fixed 600 MHz DCN314 sources; spread
spectrum is not enabled.

`amdgpu_dml` derives the geometry, buffer and clock requirements Linux gets
from DML, using `dcn3_14_ip`/`dcn3_14_soc` parameters and the
`display_mode_vba_314.c` algorithms. It computes in fixed point rather than
DML's `double`, because kernel floating point is unavailable: `x86_64`'s
soft-float target and `arch/x86_64/kernel_ctx.rs` deliberately keep no FP state
across a kernel context switch, and the aarch64 switch preserves no `d8..d15`
either. Rounding is therefore chosen per quantity instead of inherited —
required clocks, latencies and watermarks round up, buffer capacity and lines
held in the detile buffer round down — and arithmetic saturates toward a larger
requirement rather than wrapping or trapping. Formulas are rearranged where
DML's ordering would build a tiny intermediate and divide by it; the arithmetic
is equivalent and the magnitudes are chosen to stay exact.

Scope is one plane on one pipe: packed linear RGB, no DCC, no chroma
subsampling, no ODM combine, no MPC split, no DSC and no writeback — the surface
shape the boot handoff already accepts. `Config::geometry` returns the swath
width, its 256-byte-request upper bound, the swath height and the DET
allocation, refusing a viewport that exceeds the detile buffer, the linear
8192-pixel swath ceiling or the line buffer instead of approximating it.
`Config::watermarks` returns the urgent, p-state-change, stutter and Z8 stutter
watermarks in microseconds, leaving the reference-clock scaling to the register
layer. Each is a latency plus the shared extra latency, which itself is the
round-trip ping and arbiter delay over DCFCLK plus the reordering allowance and
this pipe's pixel chunk over the return bandwidth. Return bandwidth is the
smaller of what the fabric/SDP port and the DRAM can deliver after urgent
latency; it depends on the memory channel count, width and speed, which the
caller must supply from VBIOS integrated info and the DPM table rather than a
default. The WM_A entry of Linux's per-memory-type table overrides the three
non-Z8 latencies, so DDR5 and LPDDR5 differ; the Z8 times stay from the SOC
bounding box. GPUVM and HostVM are both off for a kernel-owned physical scanout,
so the page-table terms are zero rather than estimated.

`Config::prefetch` returns the prefetch schedule. It retries from DML's minimum
VStartup upward, as the mode-support loop does, and reports the first line count
that fits, or refuses the mode. TWait is taken at prefetch mode 0, which keeps
DRAM p-state change allowed and is therefore the longest wait and the largest
requirement, so a schedule that fits also fits the shallower modes. VStartup is
bounded by the nominal vertical blank, not the actual one. With no page-table or
meta bytes the four candidate prefetch bandwidths collapse to the two whose
numerators survive, and the optimised and equation-driven schedules are compared
exactly as DML compares them. The schedule uses the exact fractional
scaler-to-OPTC delay; only the register fields quantise, and they round up so
the timing generator is told about at least the delay that exists.

`amdgpu_dml_regs::Registers::new` encodes the RQ, DLG and TTU registers from
that math, following `display_rq_dlg_calc_314.c`. Every field has a fixed width
and an implied binary point, and a value that does not fit is refused rather
than truncated: a wrapped latency register does not degrade the picture, it
underflows the pipe. The 14-bit QoS high watermark holds four line times and so
binds the DCHUB-reference-to-pixel-clock ratio well below the U4.19 ratio
field's own limit; because a blank end is always shorter than a line, that
13-bit field can never overflow first. `dchub_refclk_khz` is the reference every
DLG and TTU field is expressed in and comes from the VBIOS firmware-info crystal
frequency, not from any display clock. The linear page-table geometry follows
from the pitch: a 64-byte request returns eight PTEs of a 4 KiB page, and a
pitch leaving fewer than eight PTE rows in the request buffer is refused.
MIN_DST_Y_NEXT_START follows DML's final pass, which uses the maximum VStartup
rather than the one the prefetch search settled on — the earlier of the two.
Fields this configuration cannot produce stay at the values DML yields for an
absent surface, which the module states rather than omits.

`amdgpu_dcn_dccg::Dccg::new` is unsafe: it claims the DCN314 clock generator's
register bank, which is base index 1 of the DCN IP rather than the index 2 the
HUBP, OTG, DIG and DMCUB banks use. Holding it grants no display clock mailbox —
the global DISPCLK and DPPCLK still belong to the clock manager, and this only
divides them. `set_pixel_rate_div` programs one OTG's three-bit divider pair; a
DisplayPort 8b/10b stream with one pixel per container and no ODM combine
divides by one then four, and the divide-by-four code is 3, not 4.
`update_dpp_dto` programs a pipe's DPPCLK divider as a phase over a full 8-bit
modulo, rounded up so the pipe is never starved, and refuses a request above the
global clock. A pipe with no reference clock or a zero request is parked rather
than left on a stale ratio. `set_dp_stream_clock` routes a DPIA's stream clock by
DPIA index, never a UCSI connector number. `resync_dio_fifo` copies the divider
DENTIST is really running into the request field so the DIO FIFOs restart
against the live divider. `SinglePipe` satisfies the clock manager's `Consumers`
for one pipe, adopting each new global DPPCLK as the divider reference; the DMCUB
clock notification stays with the loader, which owns that mailbox.

`Config::requirements` returns DISPCLK, DPPCLK and the deep-sleep DCFCLK floor
already rounded to frequencies the DFS dividers can produce, plus the plane's
read bandwidth. DISPCLK keeps DML's ramping margin where the DPM ceiling allows
it and drops to the unramped requirement otherwise, so no mode is refused for a
margin; a requirement above the ceiling is reported rather than clamped, leaving
the refusal to the caller.

`amdgpu_dcn_otg::Otg::new` is unsafe: it claims one OTG instance, its ODM
segment and its vertical timing generator. `program_timing` writes the mode —
counters hold one less than each total, blank starts after active plus front
porch and ends an active region later, sync starts at zero and runs for its
width, and the polarity field is the inverse of what the mode declares because
it means "negative". V_TOTAL_MIN and V_TOTAL_MAX are pinned to V_TOTAL so a
variable-refresh range left by firmware cannot retime the stream. One OPP segment
feeds the generator with the other three parked, no horizontal timing division
and no memory split. Counts that do not fit their 15-bit fields, a VStartup past
ten bits or a zero VStartup are refused. Retiming a running generator is refused
rather than allowed to tear. `enable` brings the vertical timing generator up
before the master enable and leaves the request disabled until the blank's first
line; `disable` parks every segment, drops the master enable, stops the timing
generator and waits for the block to report idle rather than assuming it.
Pixel blanking is deliberately absent: from DCN2 onwards a stream is blanked by
the OPP's display pattern generator, not by the timing generator.

`amdgpu_dcn_hubp::Hubp::new` is unsafe: it claims one hub pixel pipe, whose
scanout memory the caller must keep reserved until the pipe is blanked.
`program` writes the surface and the pacing together, because deadlines derived
for one surface do not hold for another: the request sizes, deadlines and
throttle thresholds all come from `amdgpu_dml_regs`, never from constants. The
pitch register holds one less than the pitch, the format code is not the bit
depth, and the primary address's low half is written last because that is what
arms it. A surface off a 256-byte request boundary, past the pipe's 48-bit
addressing, at address zero, or narrower than its own viewport is refused. The
chroma request sizes are cleared rather than left behind, so a previous owner's
chroma plane cannot keep fetching. `blank` waits for the pipe's outstanding
requests to retire before reporting success, so scanout memory is never released
with a fetch in flight; a power-gated pipe reads back zero and needs no wait,
and a pipe that never retires times out rather than being called blanked.

`amdgpu_dcn_plane` programs the rest of the plane path. The DPP and OPP banks are
DCN base index 2 while the MPC bank is index 3. `Dpp::program` enables the pipe
clock, sets the converter format and bypasses the scaler outright rather than
programming unity taps, with the recout and combiner size matching the active
area. `Mpc::mux_plane` binds one combiner to one DPP and one OPP and points that
OPP's output mux at it, with the bottom select parked so a stale value cannot
blend another pipe's output in, and opaque passthrough with no alpha;
`release` unroutes both ends. `Opp::program` leaves truncation, spatial dither
and frame randomisation off so the plane's depth passes through, and sizes the
pattern generator to the stream so a blanked stream covers the whole screen.
`Opp::set_blank` is where a stream is blanked: painting the pattern generator
black over the active area, and unblanking by disabling the generator outright
as DCN2 onwards requires rather than selecting a passthrough pattern.

`amdgpu_dcn_stream::Stream::new` is unsafe: it claims one DisplayPort stream
frontend, whose link encoder the caller must keep trained for as long as it
streams. This is the stream half of the DIO; the link half — transmitter enable,
training patterns and drive levels — is `amdgpu_dio`. `program` writes the main
stream attributes the sink reads to lay the pixels out: uncompressed RGB at the
given depth, sRGB full range, the totals, the active start (sync plus back porch,
the same count the timing generator uses as its blank end), the sync widths with
the polarity fields inverted because they mean "negative", and the active size.
A timing whose front porch and sync exceed its blank, whose active exceeds its
total, or whose counts pass 15 bits is refused. It then seeds the M/N rate ratio
from the link-rate code the training settled on, disabling the generator while M
and N are written because auto-measurement needs a full symbol cycle to take
over, and refusing a stream faster than its link rather than programming a
wrapped ratio. `unblank` stops the stream, resets the steering FIFO so a mode
transition's overflow cannot persist, lets the logic prime and then enables;
the hardware starts sending at the next vblank edge. Reprogramming a live stream
is refused, and both blank and unblank wait for the encoder to confirm it
stopped rather than assuming it did.

`amdgpu_dcn_display` is the bring-up sequence and owns no registers of its own.
`timing_from_edid` converts a sink's detailed timing into the shared `Timing`,
refusing interlaced modes, modes past the linear swath ceiling, and EDID whose
front porch and sync do not fit their own blanking — the last as malformed data
rather than an unsupported mode. `Scanout::reserve` takes a linear surface from
the display pool with its pitch rounded out to a whole 256-byte request, so a
line never straddles a partial one; dropping it returns the memory, so it must
outlive every pipe fetching from it. `Pipeline::plan` derives the clocks, the
HUBP registers and the global sync without touching hardware, and refuses a mode
needing more than the firmware's own DPM ceiling before any register is written.

`Pipeline::enable` drives the blocks in Linux's enable-stream order, and the
order is the substance: clocks and dividers, then timing, then the plane
programmed and deliberately blanked, then the pipe with this surface's
deadlines, then the timing generator — which from that point sends blanked
frames, which is what a sink needs to see during training — then link training,
then the stream attributes at the rate training settled on, and only then the
pipe, encoder and formatter unblanked in that order so the sink never sees a
frame the pipe was not yet fetching for. A failure at any step tears the stream
back down rather than leaving a block fetching from memory the caller is about
to release, and teardown continues past a failing step for the same reason.

A completed enable publishes the surface through `active_scanout`, and
`narf_fb::adopt_external_scanout` pulls it. Adoption is a pull because the
framebuffer crate already calls into this driver and the dependency runs one
way; it is also a policy decision that belongs to the framebuffer layer, since a
published scanout only means a stream is running, not that the console should
move to it.

`amdgpu_dcn_inventory` reads the platform constants and topology the bring-up
needs, from the platform's own tables. None of it is defaulted: the memory
configuration multiplies straight into every watermark, the DCHUB reference clock
scales every latency register, and the DENTIST VCO decides which frequencies the
dividers can produce, so a plausible guess at any of them yields a picture that
tears under load rather than an error. A table that is missing, the wrong
revision or self-inconsistent fails closed.

`display_paths(gpu, vbios)` walks `display_object_info_table_v1_4`, resolving
an exact DCN314 or Navi22/DCN3.0 profile from discovery. It decodes each path's
connector and UNIPHY transmitter separately from its hardware AUX and HPD lines.
Connector record offsets are relative to the display-object table. The I2C and
HPD record IDs are keys into `atom_gpio_pin_lut_v2_1`; the GPIO register and bit
are matched against the discovered DCN bank to obtain the AUX channel and
one-based ATOM HPD selector. `Path::aux` is `None` when absent; `hpd` is zero
when unassigned. A present malformed, duplicate or unmappable record is an error.
No GPIO ID, connector ordinal or transmitter number substitutes for an AUX or
HPD index. Unknown encoders and paths requiring an external bridge are skipped;
a table with no usable paths is refused. Record and GPIO walks are bounded.

`memory_config` takes the type
and channel count from `atom_integrated_system_info_v2_*` and the data rate from
the firmware's own DPM table, deriving the channel width from the memory type as
Linux does; a zero channel count is refused rather than replaced with Linux's
substitute of four. `dchub_refclk_khz` comes from
`atom_display_controller_info_v4_*`, keeping Linux's documented 27 MHz reference
when the table reports zero. `dentist_vco_khz` reads the PLL feedback multiplier
as 8.16 fixed point against the 48 MHz DFS reference; the CLK block is absent
from the IP discovery table so its base is hardcoded as Linux hardcodes it, which
is exactly why the result is range-checked before being believed.

`routes_for_sink(gpu, paths, sink, frontend)` matches a native sink by its
hardware AUX channel. Its transmitter and HPD selector come from that path;
the caller assigns the stream frontend independently. Shared AUX channels or
transmitters require a mux/bridge owner and are refused instead of selecting the
first connector. Only DisplayPort/eDP paths may produce native routes. Profile
bounds admit all six Navi22 transmitters and frontends. Navi22 rejects DPIA
routes; the Phoenix profile retains its five DIG candidates.

A tunnelled sink has no board-wired transmitter, so it borrows one. All five DIGs
are candidates, ordered so that transmitters the board wired to no connector come
first: borrowing one of those cannot deprive a later native plug of its fixed
transmitter. A wired transmitter is still usable while its own connector is idle,
which the hardware itself decides — `transmitter_busy` reads the backend enable
bit (DCN30 `0x20b1`, DCN314 `0x20b2`, stride `0x100`), and the link encoder
re-checks the same bit when the transmitter is actually
claimed, closing the gap between the two. The probe comes before any pipeline is
built, because building one reserves pool memory and a rejected candidate must
not cost any. A tunnelled route carries no hot-plug line, since the tunnel
reports presence itself, and its AUX index is the tunnelling endpoint rather than
a transmitter. `Pipeline::for_sink` and `Pipeline::platform` feed these into the
bring-up, so a caller no longer assembles a route by hand.

A tunnelled stream additionally needs DTBCLK and its endpoint's stream clock
routed, which the bring-up requests and programs.

`amdgpu_dp_tunnel::allocate` negotiates the tunnel's bandwidth before the link
comes up, over the sink's AUX channel, following the USB4 DP tunnelling DPCD
space and Linux `link_dp_dpia_bw.c`. A tunnel shares its host router with USB
data and with the router's other endpoints, so the bandwidth a mode needs is
asked for rather than assumed. An endpoint that does not implement allocation
reports `Unsupported`, which is not a failure: the tunnel then carries the fixed
allocation it was created with and the bring-up proceeds on that, and nothing is
written to an endpoint that cannot answer. A request is rounded **up** to a whole
allocation step, because rounding down leaves the stream short by up to a step,
and the reserved granularity encoding is refused rather than guessed since
guessing it scales every request. Where Linux clamps an over-large request down
to the router's estimate, this refuses the mode instead: a clamped request puts a
stream on a tunnel that cannot carry it, which tears rather than fails. The
router's own granted figure is believed over the request, so a router that
reports success while granting less is still a refusal. The endpoint's
non-reduced maximum rate and lane count then bound training, independently of
what the sink reports. `release` hands the bandwidth back when the stream stops,
so the router's other endpoints see it again.

The Late worker arms the bring-up once per boot, on the first discovered sink
the board can answer for, native or tunnelled. It claims only a pipe whose hub pixel pipe is blanked
and whose timing generator is stopped — the same two signals the boot inventory
uses to decide a surface is in use — so claiming one cannot disturb the internal
panel. The reserved surface is zeroed before any pixel is sent, because a
reservation comes back holding whatever was in that VRAM. A failure leaves the
display alone: `enable` has already torn its own stream down, and what remains is
the attach-only behaviour that was there before.

The attempt is deliberately one-shot. The clock manager publishes a table buffer
to firmware, so a retried failure would quarantine another reservation each time,
and re-running a sequence that failed once is unlikely to do better. A sink whose
EDID declares no usable mode does not spend the attempt.

Suspend stops the stream before the firmware, since a pipe left fetching across a
GPU suspend would read scanout memory the resume path has not re-established, but
it keeps the stream — the mode, platform constants and sink capabilities it was
validated for — so resume puts back that same mode rather than re-deriving a
possibly different one. Resume re-latches the clock levels, because the firmware
has just rebooted, and re-clears the surface, because VRAM contents do not survive
a suspend. A replay that fails drops the stream rather than leaving half of one
behind; `enable` has already unpublished the scanout by then, so the console is
back on the boot framebuffer before its memory is released.

A brought-up stream is published, and the framebuffer crate follows it. Because
that crate calls into this driver and the dependency runs one way, it installs an
observer — a function pointer, the same shape as the DRM fbdev hook — which this
module calls on both edges; the locks are released first, so an observer that
reads the published scanout cannot deadlock against the publish that woke it, and
an observer installed while a stream already runs is told immediately rather than
missing the edge. Moving the console is that crate's policy call, not this
driver's: it adopts a newly lit external display, leaving the internal panel
showing its last frame, and goes back to the boot framebuffer when the stream
goes away, since the scanout memory is about to be released.

None of this pipeline has run on silicon. That is the one remaining gap, and it
is not one more code can close: the Lenovo 50ee is the only thing that can say
whether the watermarks, the deadlines and the training are right.

Neither the attach worker nor a booted loader **programs the stream pipeline or
exposes new active DRM/KMS scanouts**. A successful firmware boot, sink read,
trained link, clock update, mode calculation or programmed divider does not
prove monitor output. The Late worker arms the sequence for a native or tunnelled
DisplayPort sink, the console follows a lit display and a stream survives suspend,
but nothing here has been confirmed on silicon.
The implementation references local Linux `amdgpu_ucode.h`,
`amdgpu_dm_dmub.c`, `dmub_srv.c`, `dmub_cmd.h`, `dmub_dcn31.c`,
`dmub_dcn314.c`, `dcn314_resource.c`, `psp_gfx_if.h`, `psp_v13_0_4.c`,
`amdgpu_psp.c`, `hdp_v5_0.c`, `dcn10_link_encoder.c`,
`dcn31_dio_link_encoder.c`, `link_dp_training_8b_10b.c`,
`link_dp_training_dpia.c` and DCN 3.1.4 register headers.

### VirtIO-GPU rendering

The Phase-B VirtIO-GPU render path is layered over the existing DRM primary
and render nodes. It is deliberately small but wire-compatible with Mesa's
virtgpu userspace ABI:

The early-console 2D resource is a transport-owned boot scanout, not a DRM
framebuffer in the card's GEM namespace. Programming it completes
`SET_SCANOUT`, so the initial DRM CRTC accurately reports an active hardware
scanout while leaving its DRM primary plane unbound (`FB_ID = 0`). This lets a
compositor validate an unchanged no-modeset page flip without synthesising an
`ACTIVE` transition. The first DRM client still owns the first DRM framebuffer
and primary-plane binding; the boot resource is never exposed as a GEM object.

- Render-node inbound: `GETPARAM`, `CONTEXT_INIT`, `RESOURCE_CREATE`,
  `RESOURCE_INFO`, `TRANSFER_{TO,FROM}_HOST`, bounded `EXECBUFFER`, and
  `GEM_CLOSE`. Handles are per-open, context creation is lazy, and opaque
  command streams are passed to a host only after size and ownership
  validation. Guest-backed resources up to the advertised per-resource bound
  may span multiple coherent DMA segments; mmap resolves pages across that
  ordered backing list. PRIME export retains the shared host resource;
  importing into another DRM open creates a new local handle and attaches the
  same resource to that open's context, as Linux's
  `virtio_gpu_gem_object_open` does. `GEM_CLOSE` removes and detaches only that
  handle. The host resource is unreferenced after its final GEM, framebuffer,
  dma-buf, and mmap reference; failed host teardown retains the backing rather
  than permitting DMA into recycled memory. A KMS framebuffer backed by such
  an import is presented directly with VirtIO-GPU `SET_SCANOUT` plus
  `RESOURCE_FLUSH` rather than copied through the boot 2D resource. Before
  that scanout read, every pending implicit `WRITE` fence from the shared
  dma-buf reservation completes; the wait snapshots the reservation and holds
  neither its lock nor the DRM mode-state lock. On a
  primary-node open, VIRTGPU-created handles are registered in the same GEM
  namespace consumed by ADDFB2; render and KMS handles on one `drm_file` must
  never diverge. DRM command words use the exact Linux UAPI structure sizes;
  in particular `GEM_CLOSE` is the 8-byte `0x40086409` request so it reaches
  that per-open teardown path before generic KMS cleanup.
- Primary-node inbound: the existing framebuffer / modeset ioctls; an
  accelerated buffer may be presented only after it is also registered as a
  KMS framebuffer. An atomic plane's non-negative `IN_FENCE_FD` resolves to
  sync-file leaves before the commit mutates KMS state; a pending leaf parks
  and retries the syscall, while a kernel-only caller uses the bounded GPU
  timeout. `TEST_ONLY` validates the descriptor but does not wait. A bad or
  non-sync-file descriptor is `EINVAL`. `PAGE_FLIP_EVENT` completions are bound to the submitting
  primary-node open, matching Linux `struct drm_file::event_list`; an event's
  opaque `user_data` must never cross to another opener, and close discards
  that opener's unconsumed events. Reads return only complete 32-byte
  `drm_event_vblank` records: an empty `O_NONBLOCK` read is `EAGAIN`, a blocking
  read waits (or is interrupted with `EINTR`), and a too-small buffer returns
  zero without consuming the event. Each open has Linux's 4 KiB event budget;
  an ioctl that cannot reserve another completion returns `ENOMEM`.
- Outbound: `EXECBUFFER` queues a fenced VirtIO-GPU `SUBMIT_3D` without waiting
  for host execution. Up to four submissions occupy private request/response
  slots on the control queue; a full pipeline waits responsively for a slot.
  The returned fence is shared by the referenced BO reservations,
  `FENCE_FD_OUT` sync-file, and binary output syncobjs. `VIRTGPU_WAIT` on a
  primary or render node is an asynchronous file operation: it parks the
  userspace task on the VirtIO-GPU controlQ completion wake (with a bounded
  timer fallback when MSI-X is unavailable), rather than busy-polling the
  fence. Poll, input fence fds, and foreign-context input syncobjs observe
  that same real device completion; dependencies on the same ordered
  context/ring do not serialize submission. Descriptor exhaustion returns
  `EMFILE` before GPU work is queued. EXECBUFFER syncobj records accept binary
  point zero and the input
  RESET flag; non-zero timeline points remain unsupported.
- PRIME dma-buf fds (dumb-buffer and VirGL exports) answer Linux
  `dma_buf_ioctl` through the generic
  [`filesystem` dma-buf core](../../../filesystem/specification/spec.md#33-file-operations-async):
  `DMA_BUF_IOCTL_SYNC`, `DMA_BUF_SET_NAME_A/_B`, and
  `DMA_BUF_IOCTL_{EXPORT,IMPORT}_SYNC_FILE`. The reservation is per buffer,
  not per fd: a dumb buffer's lives on its card `DumbBacking` (every export of
  the handle, and the handle a re-import resolves to, share it); a VirGL
  resource's lives on the shared `VirtGpuResource`, so every export and every
  importing open see the same fences. EXECBUFFER adds its device fence to each
  referenced resource's reservation as a WRITE fence, as Linux
  `virtio_gpu_array_add_fence` does, so `EXPORT_SYNC_FILE` reports in-flight
  GPU writes. VirtIO-GPU fences report driver `virtio_gpu`, timeline
  `controlq`, the virtqueue fence id as seqno, and the first observed
  completion instant as their timestamp. `VIRTGPU_WAIT` still waits on the
  BO's last EXECBUFFER fence only; fences imported with `IMPORT_SYNC_FILE`
  are not waited by `VIRTGPU_WAIT` or by a later EXECBUFFER (implicit sync of
  imported fences into GPU submissions is not implemented).
- A queued page-flip deadline remains advertised to poll until its event is
  consumed, even after the deadline expires. This closes the readiness-scan
  to park race: an event that becomes due in that interval forces an immediate
  poll retry instead of leaving the task parked without a future wake edge.
- Linux-compatible DRM devfs nodes have stable metadata shared across
  lookups. Primary and render nodes start at the conservative devtmpfs policy
  `0600 root:root`; `set_owners`/`set_perms` persist the distribution policy
  subsequently applied by udev without embedding distribution-specific GIDs.
- Each DRM card and its render node resolve to a distinct PCI sysfs parent
  carrying that card's vendor/device IDs and `DRIVER` identity. This mapping
  is required for libdrm/Mesa device discovery when multiple QEMU displays
  (virtio-gpu plus a Bochs fallback) are present.
- Once that sysfs projection is complete, the PCI parent, primary node, and
  render node emit ordered ADD uevents inside the bounded boot replay window.
  This is the interface by which udev applies the `master-of-seat` tag and
  logind reports the default seat as graphical to display managers.

## 4. Invariants & safety properties

- GPU DMA targets are validated against its IOMMU context.
- A hung GPU causes no kernel hang — the driver domain takes the hit.

## 5. Architecture notes

Stage 4 GPU candidate: virtio-gpu (software) first, then a simple real
GPU (Intel iGFX or an AMD GPU whose docs are open).

## 6. Dependencies

- **Consumes:** `drivers/` (framework), `io/` (P2P DMA), `memory/`,
  `interrupts/`, `ipc/`, `capabilities/`.
- **Provides to:** future compositor / display server.

## 7. Stage assignment

Stage 4, and may continue past Stage 4 into a post-1.0 milestone.

## 8. Resolved decisions

### 8.1 In-tree vs. userspace split (resolved)

**Decision:** **kernel owns mode-set + scanout + cursor;
userspace owns everything else** (rendering, shader
compilation, command submission, DRM-like compositing).

In-tree (under `drivers/gpu/`):
- `bochs-display` (linear FB; for QEMU emulation testing).
- `virtio-gpu` 2D mode (linear FB through virtio commands).
- Modesetting infrastructure for real PCIe display
  controllers (Stage 5+).
- `Cap<Scanout, Configure>` API gate for resolution + format.

In userspace (Stage 5+):
- 3D rendering driver (Mesa-equivalent).
- Compositing surface manager (Wayland-equivalent).
- Shader compilation.

This mirrors modern Linux's split (`drm/i915` does
modesetting in-kernel; Mesa does rendering in userspace).
NARF's strict cap model means the userspace 3D driver runs
in a sandboxed user-mode-domain with `Cap<BusDevice, Dma>`
to its GPU; no kernel-side 3D code, no kernel-side shader
compiler.

### 8.2 Minimum-viable terminal path (resolved)

**Decision:** **`graphics/console.rs` rendering 8x8 glyphs
to a linear framebuffer**, driven by whichever in-tree
driver probed (bochs-display preferred for x86_64 emulation,
virtio-gpu for both arches, real GPUs Stage 5+).

This is the same FB console already implemented in code
(see `graphics/`). The MVP path is:

1. Kernel boot → `bochs-display` or `virtio-gpu` probes.
2. `graphics/` `splash::install_console` claims the
   scanout via `Cap<Scanout, Configure>`, programs
   1024×768 XRGB8888 (or device default).
3. `console/` → `graphics/console.rs` renders each log line
   as an 8x8-glyph row.

Userspace processes that want pixels on screen open a
scanout via `Cap<FbContext, Open>` (per `user-runtime/graphics.rs`)
and submit DrawCmds through a per-process ring; the
kernel-side drain task converts to FB writes.

This is the testbin demo path (see `cargo xtask demo`) — it
works today, locked at v1.0.

## 9. ABI versioning

`drivers/gpu/` exports through SDK at `@v0`:

- `Cap<Scanout, _>` types (Read | Configure | Submit).
- DrawCmd wire format (frozen at v1.0).
- The 8x8 font glyph table — frozen so userspace renderers
  can match.

`GPU_DRIVER_ABI_MAJOR = 1`, `GPU_DRIVER_ABI_MINOR = 0`.

Stage 5+: the 3D-render userspace API (Vulkan-shaped) is a
separate spec, layered above the v1 mode-set surface.

## 10. Open questions

(none — all v0.1 questions resolved in §8)
