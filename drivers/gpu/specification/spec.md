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

### Vendor driver feature split

The crate's vendor driver sets are cargo features: `amdgpu` and
`intel`, both in `default`, so a default build compiles and
registers exactly the driver set it did before the split. With a
vendor feature off, none of that vendor's modules compile and none
of its PCI drivers register: the Intel modules,
`intel_gpu::register_pci_driver` and the `intel-gpu-pci` /
`intel-gpu-dp-bridge` initcalls exist only under `intel`; the AMD
module tree, `amdgpu-pci` and `amdgpu-usbc` only under `amdgpu`.
The `smoke_gpu_vendor_feature_registration_census` kernel-test
fixture pins the registered initcall names against the compiled
feature set. The named-config registry in build/xtask
(`configs.rs`) selects these features per build configuration:
laptop/desktop-class configs enable `intel`; `minimal` and
AMD-only configs do not. Neither vendor is offered as a loadable
module: the module loader exists, but there is no GPU-class
datapath ABI yet, so the feature gate is the selection mechanism.

### Legacy framebuffers and native mode timing

DCN3.0 DIO scanout explicitly selects `OTG_OUT_MUX = OUT_MUX_DIO` before
encoder stream attributes are programmed. Single-stream and multi-stream
timing enable both apply `mpc3_set_out_rate_control`'s output policy
(`MPC_OUT_RATE_CONTROL_DISABLE = 1`, `MPC_OUT_RATE_CONTROL = 0`) before
enabling the OPP. Neither operation depends on inherited firmware defaults;
masked updates preserve unrelated register fields. These initialization
guarantees do not by themselves establish physical HDMI sink lock.
For progressive modes, both DCN3.0 and DCN3.1.4 timing programming clear
`OTG_INTERLACE_ENABLE` and initialize the selected VTG's `VCOUNT_INIT` to
`v_total - v_front_porch`. `FP2` is
`max(0, vstartup - (v_total - v_front_porch - v_active) - 1)`.
These fields are written while the VTG is disabled, before OTG enable;
enabling the VTG preserves them. The register update preserves unrelated
bits and uses the profile's VTG instance layout.
For SCDC-capable HDMI sinks, diagnostic status is sampled both immediately
after transmitter enable and after final unblank plus the two-frame
underflow verification window, labelled `phase=transmitter` and
`phase=settled`. Missing/negative diagnostic reads do not tear down a stream;
the early sample is not treated as a settled-lock assertion.

DCN3.0 passthrough planes bypass both the MPC gamut matrix and output gamma,
and detach remap units whose status names the owned MPCC. Shared RMU mux
updates are serialized without awaiting under the lock. Physical resource
counts are 3/2/1 for DCN3.0/3.0.2/3.0.3; muxes serving another MPCC and absent
units are preserved. HDMI 2D timing also retires inherited OTG stereo/frame
packing and OPP stereo-buffer dimensions before starting the OTG.

`amdgpu_dcn30_hdmi::InfoPackets` describes AVI, HDMI Forum VSIF, gamut,
vendor VSIF, SPD, HDR static metadata and VTEM packets. `Hdmi::set_info_packets`
checks every supplied type and InfoFrame version, length and checksum before
any register write, then programs the seven slots in Linux order. Gamut/VTEM
are data packets, whose payload admission belongs to the producer. Omitted
producers and spare slot 7 are disabled. Normal desktop enable sends valid
NARF SPD identification with AVI and any required vendor frame. This packet
surface does not itself expose unsupported HDR/VRR DRM properties or select
their output color transforms.

Successful SCDC TMDS-configuration writes are followed by an async 1-ms
settling interval before transmitter enable. `link_health` distinguishes
unmonitored/non-SCDC sinks, unavailable status, acquisition, receiver lock,
and lost configuration. Lock requires matching clock-ratio/scrambling
configuration, detected clock, all three channel locks, and scrambler status
when scrambling is enabled. Legacy SCDC links also read reception flags.

The display monitor checks running single-stream and multi-stream HDMI
outputs at most once per second, with no IRQ lock held across DDC awaits.
`LinkMonitor` requests one ordinary withdrawal/relight after three consecutive
observed failures per connection. Further sustained failures report a fault
and suspend automatic recovery while retaining the context, so other working
outputs are not repeatedly reset. Unknown or missing status is not a failure.
Connector changes and explicit GPU recovery replenish the automatic budget.
`ColdBoot::check_display_hdmi_link` and `check_group_hdmi_links(due_mask)`
lend the retained display/DDC owners for those reads; stopped streams do not
perform SCDC I/O. These checks establish receiver status, not visible pixels.

`DRM_IOCTL_MODE_ADDFB` uses Linux's 28-byte `drm_mode_fb_cmd` request
(`0xc01c64ae`). It converts the legacy bpp/depth pair to a DRM fourcc and
supplies one handle/pitch, zero offsets and no modifiers to the existing
ADDFB2 validation/lifetime path. Unsupported formats, invalid dimensions,
short pitches and short dumb buffers remain rejected. Native AMD per-open
GEM framebuffers use the same conversion and retain their owner/BO checks.
Only the first u32, `fb_id`, is copied back on success. Legacy creation
retains NARF's existing DRM-master framebuffer policy and rejects render
nodes. `RMFB` dispatches Linux request number `0xaf` (`0xc00464af`);
`0xa8` is ATTACHMODE and must never remove a framebuffer.

For a connector with `NativeOutput`, GETCONNECTOR reports the exact
driver-admitted `timings` and their count, including distinct timings that
share a resolution and rounded integer refresh rate. `Connector::modes` may
deduplicate those simplified geometries; a differing list length must not
replace native timings with synthesized ones. A native output with an empty
timing list reports zero modes. Synthetic modes remain the fallback only
for connectors without native sink data. The two-pass user-copy protocol
uses the exact list count and writes modes only when the supplied capacity
is sufficient. SETCRTC and atomic admission retain their exact timing checks.

The discrete boot preflight establishes wall-time conversions before any
firmware wait. When CPU frequency probes are unavailable and the HPET
singleton is not installed, it measures the platform HPET counter through
an uncached mapping without publishing a base override or programming IRQ
comparators. Failure still rejects bring-up as `Clock`. Navi22's ROM-register
fallback admits SMUIO 11.0.6 (captured RX 6750 XT) at discovered base index
zero with ROM_INDEX/ROM_DATA dword offsets 0xe5/0xe6. SMUIO11's older
callback and SMUIO14.0.2 retain 0xe4/0xe5; unrelated revisions remain rejected.

### RX 6000 device queries, scheduling and memory pressure

`amdgpu_rdna2::metadata::vram(table, module)` bounds atomfirmware
VRAM_INFO 2.3/2.4/2.5/2.6 variable-length modules. Platform preparation reads
the module selector from BIOS_SCRATCH_4 under PCI authority and publishes it
through `amdgpu_rdna2_info::Published::vram_module`. Invalid straps fall back
to module zero; malformed tables remain unknown. `Snapshot` carries the
resulting VRAM type and bus width. `Published::pcie` holds the maximum common
endpoint/physical-partner generation and width, skipping AMD internal
switches; negotiated idle Link Status is not a maximum-capability source.
Unavailable or ambiguous partner discovery leaves the fields zero.
`Profile::mall_bytes()` mirrors gmc_v10_0_sw_init's 128/96/32/16 MiB for
Navi21/22/23/24. `Published::memory_khz` reports boot MCLK while UCLK DPM is
disabled, or GetMin/MaxDpmFreq(PPCLK_UCLK) when enabled. Publication refreshes
after boot/recovery and power-policy changes, clearing unavailable values.
The cold-boot owner retains the immutable boot clock and a fallibly copied,
validated board VBIOS. Both trained and untrained constructors preserve the
image bytes and source in their reduced GPU snapshot so reset/post can run
ASIC_Init. Recovery's fresh snapshot preserves it again after the original
controller is released. Live driver state remains with the controller.

Real device `READ_MMR_REG` ioctls on both primary and render nodes acquire a
GFXOFF reference before awaiting the platform owner. The whole register range
is checked against nv.c's unindexed GC/SDMA0/SDMA1 allow-list and BAR bounds
before one live PCI capability invocation reads it. GB_ADDR_CONFIG uses the
published topology cache. Pure `query_with` calls retain their cached-only
behavior; they never access live MMIO. Count, SE/SH indices, copy bounds and
short replies retain the existing AMDGPU_INFO ABI.

Each native ring has FIFO admission with per-waiter wakers and cancellation
cleanup. VMID exhaustion and ring throttling wait for any fence IRQ or a hard
deadline; an interrupt sequence sampled before inspecting completion closes
the registration race. Every client owns its waiter entry. CP and SDMA emit a
dedicated VM writeback after invalidation/PASID mapping and before client IBs.
`VmidManager::commit_with_flush` tracks this separately from each job's final
fence: early VM completion cannot release an active VMID. Bit 63 tags these
internal VM tickets; native job tickets use four ring bits and 27 generation
bits. Generation advances during quiesce before submitter registration, and
old submitters refuse further progress/submissions after that transition.
All-ones writeback sequences remain valid; device loss is detected through
HDP liveness, not the fence value. CP/SDMA skip reserved zero at sequence wrap
and failed submissions restore the previous sequence exactly. Media retains
zero at wrap because its nonzero ring tag distinguishes the ticket and JPEG's
two kernel IB slots must continue alternating by sequence parity.

Ordinary VRAM-preferred GEM creation also permits GTT fallback when VRAM is
unavailable, as amdgpu_bo_create sets allowed_domains, without rewriting the
reported preference. Discardable VRAM-only creation keeps its stricter domain
set; GEM_SET_PLACEMENT updates preferred and allowed normal domains with the
Linux sole-VRAM-to-GTT fallback rule.
GEM visible-VRAM pressure can evict idle buffers to GTT, including buffers
shared through same-card PRIME imports, exported fds and BO lists.
Eligible unmapped GTT buffers return to VRAM on lookup if space is available;
CS also validates listed buffers through the coordinated move path. Allocation
and copying complete before swapping backing and releasing the source; errors
preserve data, source placement and accounting. Logical identity
(`Arc<GemObject>`) is separate from an address lease (`Arc<GemPlacement>`).
Legacy CPU mappings retain both through `GemMapping` (revocable GEM/PRIME
mmap uses the `CpuMap` token described below); GPU VA records retain both,
including split and deferred records. Deferred CPU user-fence writes retain
a `GemMapping` until the write completes. Acquiring a placement lease and
claiming exclusive backing for a move use the same per-object lock; object
handles, PRIME exports and BO lists do not pin placement by themselves.
`VmState::for_card` registers weak shared VM state for coordinated rebinding;
its constructors now allocate shared state at runtime. `amdgpu_vm::relocate`
requires the card's placement guard: it waits for every affected VM's last job
on each ring and for reservation fences before releasing GPU address leases.
Wait failure or cancellation leaves mappings untouched. CPU-visible copying and PTE
rewriting run synchronously under admission exclusion; errors restore
leases to unchanged backing. Existing table allocations and virtual addresses
stay fixed; TLB sequences advance before another submission can run.
The card gate spans native queue publication, `note_job`, and reservation-fence
attachment. Dependency waits precede gate acquisition. User GEM_VA ioctls park
for this gate through `dispatch_async`; synchronous dispatch reports Busy on
contention. GEM_CREATE and native CREATE_DUMB take admission before even
their fast allocation path: sync entry tries the gate (Busy on contention),
and async entry parks, then borrows that one guard across heap lookup,
reservation/zeroing, reclaim and CARD_OBJECTS/handle publication. Lookup's
opportunistic promotion also requires a successful nonblocking live guard;
an already-admitted VM/CS caller retains current backing until its coordinated
move. No client can repopulate a heap after reset's eviction snapshot or
continue allocating through a captured heap after it is withdrawn.
`amdgpu_gem::dispatch_async` retries a strict VRAM create after
reclaiming GPU-mapped buffers; ordinary allocations retain GTT fallback.
Placement exclusion is one permanent mutex/readiness cell per append-only DRM
card registration, published once under a short lookup lock. The cell and
lookup slot are fallibly allocated on first admission and retained for the
card's lifetime; permanent reset quarantine cannot block an unrelated card.
Client paths use `lock_placement_live` (or synchronous `try_placement_live`):
terminal `mark_placement_lost` wakes every already-queued client and refuses
new placement, VA, allocation and KMS work with NoDevice, even when an unsafe
reset must retain its guard forever. Cancellation removes both mutex and
loss waiters. Temporary suspend retains exclusion without marking loss;
successful resume releases it normally. Internal reset code may retain the
infallible guard API; close and release do not require new placement admission.
Unregistered VM mappings, deferred CPU user-fence writes and legacy raw
address leases (`GemMapping`, `mmap_lifetime`) still pin backing. GEM and
PRIME `mmap_backing` instead return a revocable `CpuMap` token
(`amdgpu_gem::cpu_mapping`), requesting `MemoryType::WriteCombining` for
the mapping. User BAR leaves select PAT WC on x86_64 or MAIR Normal-NC
on aarch64, matching the kernel's prefetchable BAR and framebuffer mappings.
System RAM leaves stay write-back to match the kernel direct map. The VMA
retains the WC request across VRAM/GTT migration, fork and mprotect;
relocation recomputes each destination leaf's cache type, including rollback.
One `CpuBacking` per object holds the current
placement lease and registers every frame of that generation with a count of
external metadata aliases (`retain_cpu_frame`/`release_cpu_frame`, reached
through the filesystem alias hooks), so the backing survives fork's interval
before owner publication. A token is pending until `mmap_published`; pending
tokens, a moving backing, and any extra placement lease refuse the move
(`Busy`). `amdgpu_vm::relocate`'s CPU-visible path allocates the destination
and registers its rows, samples an empty reservation set and its generation,
then asks the VM to revoke every CPU alias. The frozen commit releases the
backing lease, rechecks exclusive ownership, domain and resv generation, copies
and swaps placement without allocating or sampling fences; errors restore the
lease and old frames. A backing retires (rows and lease dropped) only once no
token and no alias remain, and a retired backing is never reused.
RX6000 invisible VRAM supports asynchronous staged copying
to GTT and promotion of NO_CPU_ACCESS GTT buffers back into invisible VRAM.
`UnmappedHeap::transfer` optionally supplies `VramTransfer::read/write`; the
coordinator retains old GPU leases until the entire private copy completes,
then commits backing and rebinds PTEs without awaiting. Errors or cancellation
preserve the original placement. The native SDMA5.2 worker uses a reserved
1 MiB BAR window, ordered clears/copies and real current-generation fences.
Each queued copy retains its allocations independently of its waiting task
and attaches a KERNEL reservation fence to the source BO. Stage reuse waits
for the previous copy even after cancellation. Upload staging is refreshed
from the retained GTT source on every recovery replay. Reset exclusion,
current PCI capability invocation and a GC power reference protect CPU BAR
accesses; an epoch change invalidates an unconsumed readback. A reset, timeout
or device loss never signals unfinished kernel work as complete. Recovery
publication restarts queued work. CS re-samples live mapped/listed BO KERNEL
fences under placement admission and after attempted promotion, with bounded
waits before publishing user work. NO_CPU_ACCESS also rejects forged GEM and
PRIME CPU mappings after a move into GTT. Completed deferred
holds can be retired while checking progress; `amdgpu_cs::retire` samples
completion callbacks outside its resource lock, then revalidates tickets.
`GemObject::preferred_domains()` reads the atomic
preference; GEM_SET_PLACEMENT records normal-domain bits without moving a
pinned object. GEM mmap resolves scattered GTT pages through `frames`, never
by assuming consecutive physical addresses. This is a bounded placement and
eviction policy, not the complete Linux TTM feature set.

### Shared RDNA2 execution and family limits

The shared public modules use `amdgpu_rdna2_{boot,platform,gating,power,
power_policy,power_saving,gfxoff,thermal,tdr,recovery,cs,kms,modeset,display,
scanout,submit,bios}` names, with matching canonical names for shared firmware,
queue and hardware backends. `amdgpu_rdna2_board_power` is the board-table
parser; `amdgpu_rdna2_power` publishes runtime power samples. Existing Navi22
paths re-export the same modules, preserving type identity and source
compatibility.

`amdgpu_rdna2::options::BootOptions::parse(cmdline)` yields
`{native_display, accel, multi, hw_cursor, power_saving}`. Switches
`amdgpu.native_display`, `amdgpu.rdna2_accel`, `amdgpu.rdna2_multi` and
`amdgpu.rdna2_hw_cursor` accept a bare flag or `=1|on|y|yes|true` (on) and
`=0|off|n|no|false` (off); any other value keeps the default. The
corresponding `amdgpu.navi22_*` spellings remain aliases; the canonical name
wins. Defaults: native display, accel and hardware cursor on; multi-display
off (secondary CRTCs cannot present or deliver vblank yet). `power_saving` is
the `amdgpu.rdna2_pg=` list, or `DEFAULT_POWER_SAVING` (every feature) when
absent; `=none|off|0` or an empty value applies nothing. The first canonical
power value takes precedence over the first legacy value, including an empty
or invalid canonical value; invalid power lists enable nothing. Defaulted
power features still pass every display-admission and driver prerequisite.

Clock/power capability flags come from each profile's Linux
`nv_common_early_init` selection. Navi21/22/23 share the existing capability
set; Navi24 omits JPEG CG/PG. Gating resolves exact PCI/GC/MP1/SDMA identity,
compatible hub/controller banks and one through four discovered engines;
absent SDMA engines are never accessed. ROM handling selects the discovered
SMUIO backend: the older backend skips disabled ROM gating, while the newer
backend explicitly forces ROM clocks on.

SMU telemetry selects `SmuMetrics_t`, `_V2_t` or `_V3_t` using exact per-ASIC
firmware thresholds from `sienna_cichlid_get_smu_metrics_data`. SMU11's shared
THM11.0/SMUIO11.0 register layouts are resolved through discovered banks;
missing, duplicate, truncated or other-generation banks remain unavailable.
Firmware interface diagnostics use the ASIC-specific driver interface version.

`ColdBoot::new_rdna2` validates the exact PCI/GC/PSP identity and matching
SOS, SMC and graphics bundle before device I/O. Recovery rebuilds through
that constructor and retains the boxed sequence owner used by native Navi22.
Native probe eligibility includes all inventoried PCI IDs. Hardware validation
beyond the existing Navi22 path remains outstanding.

Production SDMA queues use the contiguous discovered engine count (one to
four). Repeated SDMA0 instances name engines by instance; separate SDMA0/1/2/3
hardware IDs with instance zero name engines 0/1/2/3 (the RX 6750 XT reports
SDMA0:0 and SDMA1:0). Both encodings are normalized before checking for
duplicate engines and holes; numbered IDs with nonzero instances are refused.
Engines 2/3 use GC bank 2
and distinct doorbells, fences and IH routes. Client ring IDs 8/9 preserve
existing media IDs; tickets reserve four low bits for the ring ID and VM
retirement tracks sixteen slots. Absent engines have no fence mapping.

SMC 2.1 containers select a PowerPlay table by its exact VBIOS board ID,
without falling back to another board. Profile-specific power table layouts
validate format, revision and size before overlaying board data. Navi24
accepts both the original 1700-byte and later 1888-byte SMC layouts, whose
board ranges are checked against the corresponding Linux interface headers.

DCN 3.0/3.0.2/3.0.3 expose six/five/two pipes, streams and native channels.
Resource allocation and constructors enforce those capacities. DCN 3.0.3
does not access the removed plane/DSC power-gating registers. DML selects
the corresponding stutter latencies, round-trip cycles and DPTE capacity.
VCN 3.0.33 starts decode without programming encoder rings; its video-capability
reply contains H.264, HEVC and VP9 decode and an empty encode table, matching
Linux `nv_query_video_codecs`. Other supported VCN revisions retain their
appropriate Sienna Cichlid codec tables and harvested-instance selection.

### AMD discrete PCIe probe and VRAM

`AmdGpu::bring_up` probes MM_INDEX with the aligned byte address `0x378c`,
then restores its previous selection without accessing MM_DATA. Navi22 and
Raphael discard the latch's low address bits; an unaligned magic value is
not a valid presence test. Indexed register helpers accept DWORD register
IDs and scale them to byte addresses at the MM_INDEX boundary. Unrepresentable
IDs and addresses selecting the VRAM mode perform no device I/O (reads return
all ones). The separate VRAM accessor retains its explicit memory-mode and
MM_INDEX_HI protocol. All register-port operations retain exclusive latch
ownership and current PCI authority.

`amdgpu_rdna2::PROFILES` inventories the discrete Navi21, Navi22, Navi23 and
Navi24 ASICs using exact PCI IDs from Linux `amdgpu_drv.c::pciidlist`, including
mobile and professional variants. `for_pci_id` rejects other vendors and holes;
no range match or marketed SKU determines the ASIC. Each profile supplies its
own SOS, SMC, SDMA, graphics, VCN and DMCUB container names. This is an inventory,
not a load order or a claim that every container is required on every board.
The existing Navi22 loaders consume that same inventory.

PCI registration and native startup eligibility include all inventoried IDs.
The shared coordinator validates the discovered IP versions, matching firmware
bundle and board policy; identification alone does not bypass these checks.
Legacy firmware loading is rejected for every discrete RDNA2 ID; Rembrandt
retains its separate APU path. Existing `amdgpu.navi22_*` boot options name the
shared discrete path as compatibility aliases for the canonical RDNA2 options.
Native Rust tests under `drivers/gpu/amdgpu/rdna2` exercise exact PCI
identity, ASIC-specific firmware inventories, serialized PowerPlay boundaries
and integration with registration/`ChipInfo`. Firmware parsers validate
container structure; model results establish neither firmware authentication
nor device execution.



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

A bound Navi 22's `AMDGPU_INFO` replies come from `amdgpu_info_navi22`
(`query`, `query_with(snapshot, Submission, query, payload)`), which mirrors
`amdgpu_kms.c` for this ASIC: DEV_INFO (`chip_rev`/`external_rev = rev + 0x32`,
`pci_rev`, harvested CU/AO bitmaps, RB and TCC masks, CE RAM, DPM GFXCLK
range), HW_IP_INFO with IP-block versions (GFX/compute 10.0, SDMA 5.2,
VCN/JPEG 3.0) plus discovery versions and Linux IB alignments, HW_IP_COUNT,
FW_VERSION from the loaded file headers and `GetSmuVersion`, READ_MMR_REG for
GB_ADDR_CONFIG (0x263e; other offsets EFAULT) and MEMORY/VRAM_GTT with the
8 MiB VM reservation. `Snapshot::navi22: Published { topology, pci_revision,
boot }` carries the inputs, published by `amdgpu_info::publish_navi22_topology`
(cold-boot `Stage::ReadTopology`, appended after `FenceInterrupts`),
`publish_navi22_pci_revision` (platform prepare) and `publish_navi22_boot`
(after a successful cold boot, from `ColdBoot::uapi_versions` and the
report). Unpublished inputs leave the corresponding fields zero.
`amdgpu_info_navi22::SUBMISSION` is the single switch for ACCEL_WORKING,
`available_rings`, HW_IP_COUNT, GANG_SUBMIT, the DRM minor (3.64.0 vs
3.0.0) and the render ioctls; it is `Wired`, and still advertises nothing
unless `Boot::queues_verified`. Media IPs additionally need
`Published::media_rings` (`publish_navi22_media_rings`, from
`amdgpu_vcn_navi22_cs::register`): VCN_DEC/ENC/JPEG report one ring each
when their rings passed, HW_IP_COUNT(VCN_DEC/ENC) is `num_vcn_inst` (every
discovered instance, harvested ones included) and JPEG 1. VIDEO_CAPS
returns the Sienna Cichlid codec tables for the published harvest; MAX_IBS
reports
`amdgpu_navi22_submit::MAX_IBS` (16) for advertised rings.

`unsafe amdgpu_gfx10_topology::read(gpu, pci_cap)` requires exclusive GRBM
selector ownership with RLC booted and GFX powered. It samples the NBIO
revision strap, GB_ADDR_CONFIG, per-SE/SA fused and user RB/WGP disables and
the TCC disables, restores SE/SA broadcast within one capability operation,
and checks selector readback using only GRBM_GFX_INDEX's defined fields;
reserved read bits cannot invalidate a correct selection. A mismatch in a
defined selector or broadcast field still fails with `Readback`.
`derive(Limits, &Sample)` reproduces `gfx_v10_0_setup_rb`,
`gfx_v10_0_get_cu_info` and `gfx_v10_0_get_tcc_info`. A zero or non-256 B
interleave GB_ADDR_CONFIG, zero CUs/RBs, or GC dimensions beyond the GFX10
DRM layout are refused; only device loss or revoked authority fails the
cold-boot stage.

### RDNA4 family: Navi48 and Navi44 (RX 9000)

Every "Navi 48" section below applies to both RDNA4 dies. The `navi48`
module, function and test-subsystem names predate Navi44 and are kept; what
selects a die is `amdgpu_rdna4::Rdna4Chip`.

**Identification.** Linux binds RDNA4 through `amdgpu_drv.c`'s generic AMD
`PCI_CLASS_DISPLAY_VGA` / `_OTHER` entries (`CHIP_IP_DISCOVERY`) and decides
everything from the discovery blob. NARF does the same: the class-match
backstop reaches `probe` for any AMD display function; `AmdGpu::bring_up`
reads discovery even for an unlisted device id, and binds it as
`Family::Navi4` when exactly one GC0 is 12.0.0 or 12.0.1 (other unlisted ids
still return `UnknownAsic`). `Rdna4Chip::of(gpu)` is the only RDNA4 gate:
AMD vendor, `Family::Navi4`, a device id the PCI table does not give another
family, and one GC0 of 12.0.1 (`Navi48`) or 12.0.0 (`Navi44`).
`ChipInfo::asic` follows the discovered die (`"navi48"` / `"navi44"`), and
`ChipInfo::revision` holds the PCI revision (config 0x08) read at probe.
`amdgpu_rdna4::KNOWN_DEVICES` is the one RDNA4 PCI id list — 1002:7550
(RX 9070 / 9070 XT / 9070 GRE), 1002:7551 (Radeon AI PRO R9700),
1002:7590 (RX 9060 XT) — used only for exact bus matches, the probe log's
`pci.ids` name and tests; the RX 9060 and OEM ids bind by discovery alone.
`amdgpu::NAVI48` remains a named constant, not a gate. `is_navi48()` /
`claim_navi48()` match any RDNA4 die. Register banks accept
`amdgpu_rdna4::GC_VERSIONS` (12.0.0, 12.0.1: one `gc_12_0_0_offset.h`) and
`MP_VERSIONS` (14.0.2, 14.0.3: one `psp_v14_0` / `smu_v14_0_2_ppt`).

**Linux differences, and what NARF does with each.** Everything not listed is
one shared code path in Linux (one `case` for both versions):
`soc24_common` cg flags, `gfx_v12_0` (golden sequence, queue/MEC counts,
`max_hw_contexts` 8, cleaner shader and per-queue reset firmware minimums,
GFXOFF, clock gating), `imu_v12_0`, `mes_v12_0`, `gmc_v12_0` (GFXHUB 12.0,
48-bit 4-level VM, UMC 8.14 RAS functions, `amdgpu_atomfirmware_get_umc_info`
for VRAM type/width), `sdma_v7_0`, `ih_v7_0`, `vcn_v5_0_0`, `jpeg_v5_0_0`,
`psp_v14_0` (SOS + TA, `sup_ifwi_up`, mode-1 reset in `soc24_asic_reset_method`,
no FW attestation), `smu_v14_0_2_ppt` (one driver interface 0x2E, one
`smu14_driver_if_v14_0.h` / `smu_v14_0_2_pptable.h`, PMFW-owned feature
handling on suspend/unload), DC's `DCN_VERSION_4_01` resource with
`res_cap_dcn4_01` (four pipes, DMUB `dcn_4_0_1_dmcub.bin`) and one DML2.1
SoC bounding box (`dml2_socbb_dcn401` + `dml_dcn4_variant_a_soc_qos_params`,
then overwritten from the SMU clock table, VBIOS `vram_info` channels and
DCHUB reference — there is no per-SKU bounding box).

| Linux site | GC 12.0.1 / MP 14.0.3 (Navi48) | GC 12.0.0 / MP 14.0.2 (Navi44) | NARF |
| --- | --- | --- | --- |
| `soc24_common_early_init` `external_rev_id` | `rev_id + 0x50` | `rev_id + 0x40` | `Rdna4Chip::external_rev` on `rev_id`, the NBIO `STRAP_ATI_REV_ID` strap (`amdgpu_rdna4::rev_id_strap`: `nbif_v6_3_1_get_rev_id` / `nbio_v7_7_get_rev_id`, BASE_IDX 2), read by the probe — never the PCI revision; DEV_INFO `chip_rev`/`external_rev`, plus `pci_rev` (`pdev->revision`) and `mall_size` (`amdgpu_discovery::mall_size`, MALL_INFO less harvested UMCs) once the probe publishes `Rdna4Identity`. Every 4-bit strap lands in Mesa's `AMDGPU_GFX1200_RANGE` [0x40, 0x50) / `AMDGPU_GFX1201_RANGE` [0x50, 0xFF) (`mesa_external_rev_range`). An unreadable PCI revision or strap fails the RDNA4 probe (Linux never enumerates such a function) |
| `soc24_common_early_init` pg_flags | VCN, JPEG, VCN_DPG, **JPEG_DPG** | VCN, JPEG, VCN_DPG | `jpeg_dpg()` recorded; both start JPEG/VCN statically (no DPG) |
| `kfd_device.c` gfx_target_version | 120001 (gfx1201) | 120000 (gfx1200) | `gfx_target_version()`; no KFD |
| `gfx_v12_0`, `imu_v12_0`, `mes_v12_0` firmware | `gc_12_0_1_{pfp,me,mec,rlc,imu,mes,mes1,uni_mes,toc}` + RLC/IMU kicker | `gc_12_0_0_*`, no kicker | `GC_12_0_1_FW` / `GC_12_0_0_FW` (TOC is RLC-backdoor only, never loaded) |
| `psp_v14_0`, `smu_v14_0` firmware | `psp_14_0_3_{sos,ta}`, `smu_14_0_3`, + kicker builds | `psp_14_0_2_{sos,ta}`, `smu_14_0_2` | `MP_14_0_3_FW` / `MP_14_0_2_FW`, chosen by the discovered MP revision |
| `sdma_v7_0` firmware | `sdma_7_0_1` | `sdma_7_0_0` | chosen by discovered SDMA0 revision |
| `amdgpu_is_kicker_fw` | 1002:7551 rev 0xC8 → `_kicker` SOS/TA/SMU/RLC/IMU | — | `is_kicker`; `FirmwareSet`, `Target::Psp14_0_3Kicker` |
| `amdgpu_ras_asic_supported` | MP0 14.0.3 listed | not listed: `ras_hw_enabled = 0` | `amdgpu_navi48_ras::asic_supported`; Navi44 arms no RAS source |
| `psp_update_fw_reservation` | SOS ≥ 0x3a0e14 | SOS ≥ 0x3b0e0d | `Psp::update_fw_reservation_navi48` on the SOS descriptor's `fw_version` (`Image::sos_version`), in the cold boot's `Ring` stage after the KM ring and before the TMR (skipped by the `after_reset` owner, as Linux skips it in reset/suspend); `FB_FW_RESERV_ADDR` then `_EXT_ADDR`, `PSP_ERR_UNKNOWN_COMMAND` = none, other statuses only warned, a region not ending at VRAM's top skipped; both pinned (1 MiB-rounded) in the BAR pool and the unmapped pool by `claim`; a lost fence, a range past VRAM or one overlapping a live allocation fails the boot. Deviation: the VBIOS-sized `FirmwareTail` stays protected (NARF never returns protected VRAM), so a smaller PSP region does not free the difference |
| `smu_v14_0_2_enable_gfx_features` | `-EOPNOTSUPP` | `EnableAllSmuFeatures(FEATURE_PWR_GFX)` | mode-2-reset hook only; no NARF path uses it |
| `smu_v14_0_2_get_gpu_metrics` energy accumulator | PMFW ≥ 0x685000 | never | not exported |
| `dcn401_calc_num_avail_chans_for_mall` clamp | 16 channels | 8 channels | `mall_channel_limit`, `mall_bytes` (4 MiB/channel) |
| `dcn401_resource_construct` `dcc_plane_width_limit` | none | 7680 | `dcc_capable` reads the bound die |
| `dcn401_is_ppclk_idle_dpm_enabled` | PMFW ≥ 0x681800 | PMFW ≥ 0x661300 | recorded; UCLK/FCLK stay pinned |
| `dcn401_is_df_throttle_opt_enabled` | never | PMFW ≥ 0x663500 | recorded; no SubVP |
| `gmc_v12_0_sw_init` ECC IRQ client | `SOC_V1_0_IH_CLIENTID_DF` | `SOC21_IH_CLIENTID_DF` | both 0x17: no difference |

DAL's `dal_asic_id.h` names its ranges the other way round
(`GC_12_0_0_A0 = 0x50` is IP GC 12.0.1; `GC_12_0_1_A0 = 0x40` is GC 12.0.0);
the table and `Rdna4Chip` are by IP version.

**Board values from hardware, not Navi48 constants.** Shader engines,
arrays and CUs come from discovery's GC table (maxima) and GC12's
fused/user disable registers (`amdgpu_gfx12_topology`), so a 9070 GRE or
9060 XT reports its own CU, RB and bitmap. VRAM size is `RCC_CONFIG_MEMSIZE`;
type and bus width are VBIOS `umc_info`; DML's channel count is DALSMC
`GetNumUmcChannels`; DPM clocks, PPT limits, thermal limits and fan range are
the PMFW board table. The DCN resource pool comes from `CC_DC_PIPE_DIS`
(`dcn_4_1_0_offset.h` 0xca, BASE_IDX 2): `unsafe
amdgpu_rdna4::read_pipe_pool` reads it in every boot owner's construction
(cold boot and `after_reset`'s recovery/resume owner) and
`publish_pipe_pool` records the `PipePool` (`pipe_pool()`, all four pipes
if the read fails) before any display owner is built. The pool is per
device: `amdgpu_rdna4::publish` at bind resets it to all four pipes, so no
previous device's fuses survive (NARF binds one AMD GPU at a time). `PipePool` is `dcn401_resource_construct`'s packing:
`count()` surviving pipes, pipe index `j` (`pipes()`, `all()`) backed by
the `j`-th unfused instance (`hw(j)`, inverse `pipe(inst)`, `hw_mask` /
`pipe_mask` by bit) for its HUBP, DPP, OPP, OTG and MPCC, and DSC `j`
(`dsc(j)`, dcn20_acquire_dsc's one-to-one map; all four DSCs survive).
`available_pipes()` (the pool's count) caps DML's TotalAvailablePipesSupport
and the mcache phase's free pipes.

**Pipe harvesting (DCN401 pipe index vs. instance).** As in DC, every
`u8` pipe in the display stack is a pipe index (`pipe_ctx->pipe_idx`):
`otg::Request::pipe`, `SplitPipes`, the per-pipe `Status` and sibling
records, `dccg::Request::pipe`, the selected display, `Modeset::pipe`, the
modeset planners (a DRM CRTC is not a pipe: its stream's head pipe is
acquired). Each owner snapshots the published pool in its layout
(`otg` `Layout::pool`, `dccg` and `clk` likewise) and every per-pipe
register is addressed at the index's instance: OTG/ODM/VTG, OPP, DPP/CM,
HUBP (and its cursor), DOMAIN0-3 power gating, the MPCC (its DPP's
instance) with its OGAM/MCM, MPC_OUT and the per-OPP cursor lock,
DCHUBBUB_DET{hubp->inst}, DPPCLK{dpp->inst}, OTG{tg->inst}_PIXEL_RATE,
DP_DTO, DTBCLK_P and PIXEL_RATE_DIV and their gates. Every field naming an
instance carries the instance: MPCC_TOP_SEL/BOT_SEL/OPP_ID/UPDATE_LOCK_SEL,
MPC_OUT_MUX, OPTC_SEGn_SRC_SEL and the ODM line memories,
OTG_MASTER_UPDATE_LOCK_SEL, HUBP_VTG_SEL, the DIG frontend's OTG and stereo
sync source, the HPO DP and FRL stream encoders' pixel source,
DPSTREAMCLK/HDMISTREAMCLK sources, DCCG_AUDIO_DTO0_SOURCE_SEL, the DSC's
OPP source and the DMUB TMDS pixel-clock controller id. The DSC is the
pipe index's (`PipePool::dsc`, DSC registers, DOMAIN16-19 and DSCCLK
untranslated). Stream and link encoders, PHYs and audio endpoints are not
pipe resources: fusing leaves them, and the DIO/HPO stream encoder a
display uses, unchanged. Every whole-hardware sweep (plane retirement,
idle and power checks, running timing, DET grants) walks `pool.pipes()`;
the clock owner's idle witnesses of a fused OTG are `(0, 0)` and never
read. DCHUBBUB's DET sizes are read for all four instances, as
dcn401_init_crb and dcn401_program_compbuf_segments do. MPC is separately
unfused: whole, unshared plane retirement initializes all four physical
MPCC selectors and output muxes, including the ones belonging to fused pipe
indices, as dcn10_init_pipes sweeps all four `res_cap->num_opp` MPCCs.
Only their selector and update-lock registers are accessed;
fused HUBP/DPP/OPP/OTG blocks remain inaccessible. A retained sibling display
limits retirement to unowned pool pipes, leaving the other physical MPCCs
untouched. OTG/HUBP interrupt sources name instances and count
for `pool.pipe(inst)` (`DisplayEvents` by pipe; a fused instance's event is
unhandled). Planners and the platform take only pool pipes: DC's
acquisition (below) searches the pool's pipe indices, `route_streams` and
the CRTC routes refuse CRTCs past the pool, and KMS publishes `amdgpu_navi48_kms::
crtc_count()` (Linux's `max_streams`, the pool's count) CRTCs with
`possible_crtcs` limited to them. Model tests run the scanout chain, ODM,
overlay/underlay/MPC trees, plane updates, cursor locks, timing, DSC, DCCG,
interrupt mapping and planning on pipe-0-fused, pipe-1-fused and
pipes-1-and-2-fused boards (`amdgpu_dcn401_harvest_tests.rs`: `Renamed`
shows a full-board model to the harvested owner and panics on fused pipe
blocks or fields naming them, with the physical MPC selector exception;
`guard`/`guard_raw` enforce the same rules for models
addressed by the owner itself).

**Pipe acquisition (DCN401).** `amdgpu_dcn401_resource::DcState` is DC's
`dc_state` reduced to pipe acquisition: each pool pipe's `PipeCtx` (stream,
plane, top/bottom and ODM links by pipe index) and the streams with their
planes in `stream_status` order, on a pool of `pipe_count` pipes. Its
methods are Linux's, with `self` the new state and `cur` the current:
`add_stream` (dc_state_add_stream; the OTG master by
acquire_otg_master_pipe_for_stream: a pipe the current state used as an
OTG master, else one it left free, else one it used as a secondary DPP,
else any free pipe, else an MPC split), `remove_stream`, `add_plane`
(dc_state_add_plane: the first plane on the OPP heads, a further one on a
secondary DPP per OPP head by dcn32_acquire_free_pipe_as_secondary_dpp_pipe
(a free pipe of the current blending tree at that OPP head's index, else
one the current state left free, else a current MPC slice, else any) and,
short of pipes, every stream's MPC combine dropped, then the stream's ODM
slices one by one), `remove_plane`,
`update_pipes_for_stream_with_slice_count` (further OPP heads by
dcn32_acquire_free_pipe_as_secondary_opp_head: the current OTG master's
further OPP heads at that index first, then one the current state left
free, then any) and `update_pipes_for_plane_with_slice_count`, and
`map_pipes` (map_dc_pipes_with_callbacks with DML's per-stream `Target`:
every reduction, then every increase, stream by stream). DSC needs no
state: DCN401 has a DSC per OPP, dcn20_acquire_dsc's one-to-one branch.
Every mutating method takes a `Scaling` (resource_build_scaling_params on
one pipe of the state): a plane appended
(resource_append_dpp_pipes_for_plane_composition) that cannot scale on
one of its pipes is removed again, and a slice count change
(update_pipe_params_after_{odm,mpc}_slice_count_change, run when the count
changes) fails when one cannot scale, the change itself standing, as in
DC; acquire_first_split_pipe rescales the pipe above, its result unchecked.
`ScalesAnywhere` always scales.

**Pipe acquisition (Navi48 configurations).** Every pipe a configuration
takes is DC's choice over `DcState` (`modeset::{light_pipes, beside_pipes,
live_pipes, head_pipes, dc_state, StreamPipes}`), never a fixed one and
never CRTC k's pipe k. `dc_state(running)` is the current state the
running displays record (`dc->current_state`): each stream (id its CRTC)
on its OTG master `Modeset::pipe`, every ODM slice's OPP head after it, and
in each slice its planes' blending tree in DC plane order, each plane's MPC
slices together and every plane's slices linked across the segments, as
DC's own acquisition leaves them. A stream's DC plane order is its primary
first (NARF scans the primary out on the OTG master and its OPP heads),
then the overlays top first (amdgpu_dm's descending zpos). Each flow
builds the new state as amdgpu_dm's atomic check does, every plane's
scaling on each pipe being the scanout's own SPL on that pipe's slice
(`PlaneScaling`: `stream_planes` and `SurfaceRequest::scales_on` over the
configured streams' `StreamPipes::selection` and, for `beside_pipes` and
`live_pipes(current, s, reset, running)`, the running displays'; an
admission stand-in from `StreamPipes::of_plan` always scales), and reads
every stream's head and further pipes (`DisplayPipes`) back from it:
- `light_pipes(current, streams)`: a configuration lit anew
  (`modeset_routed`; the platform passes the displays it stopped for the
  relight as `current`, one commit as amdgpu_dm modesets them together; a
  first lighting passes an empty state): every running stream and plane
  removed, the new streams added in CRTC order (`add_stream`: a pipe the
  current state used as an OTG master first, so a relit configuration
  keeps its OTG masters), their planes, then DML's counts
  (`StreamPipes::target`: the plan's ODM slices, each plane's MPC slices,
  one on an ODM stream). `head_pipes` is the OTG masters alone;
  `plan_pipes`/`display_pipes` are it over no running display (stand-in
  pipes for admission checks, `display_admits_planes`).
- `beside_pipes(current, streams, running)`: new streams beside the running ones
  (`modeset_beside`; the running streams and planes kept): their OTG
  masters (a pipe the running state leaves free first), planes and counts;
  `None` (a relight) when that would move a running stream's pipes.
- `live_pipes(current, stream, reset, running)`: a running display's planes changed
  (`update_display_planes`): with `planes::planes_reset`
  (should_reset_plane: any non-cursor plane added or removed, or a change
  of its source/destination size (not position), rotation, pixel blend
  mode, 16-bit alpha, COLOR_RANGE/COLOR_ENCODING, framebuffer format or
  modifier, or normalized zpos; a plane only moved keeps its pipes;
  compared on the DRM plane states `PlaneSetup::drm` (`DrmPlaneState`)
  that `drm_native_planes` records, or for a setup not from DRM on what DC
  is given; `PlaneSetup::is_full_frame` is the full-frame primary alone
  whatever states it records) every plane of the stream removed and added again
  in DC plane order, then the counts; a recreated overlay takes the first
  free pipe of its OPP head's current blending tree, so it comes back to
  its pipe wherever it moved in the stack and a new plane takes a removed
  one's (Linux swaps a primary's MPC slice the tree gives an overlay first
  to a free pipe); `None` (a modeset) when the stream's OTG master or OPP
  heads or another display's pipes would move.
Everything downstream follows the chosen pipes: the CRTC's head pipe for
its timing, OPP, blank, DSC (the pipe index's), DCCG and pixel clocks,
deadlines and DET, cursor and MST link owner, its present, vblank and
cursor tasks (`crtc_pipe`) and DisplayEvents (by pipe).

**Stream encoders (Navi48 configurations).** The encoders are DC's choice
too, made in the same `DcState` right after each new stream's OTG master,
as resource_map_pool_resources makes it (`StreamPipes::on(StreamOutput)`:
the stream's board port as its link, its transmitter's DIG as the link
encoder's preferred engine, whether it codes 128b/132b and has sink audio;
`DcState::map_stream_encoders`): a DIO stream encoder for every stream
(dcn10_find_first_free_match_stream_enc_for_link: the free preferred DIG,
else the last free one), and on a 128b/132b DP stream the first free HPO
DP stream encoder and its link's HPO DP link encoder
(add_hpo_dp_link_enc_to_ctx: the one the link holds, retained, else a
free one; one per link however many MST streams ride it), refusing the
state without one. Audio-capable streams also acquire an Azalia endpoint
with Linux's `find_first_free_audio`, using the DIO stream encoder's engine
for every transport: the matching free endpoint, otherwise the first free
endpoint. No free endpoint leaves video enabled without audio. The state
retains this assignment in `StreamEncoders::audio` and excludes it from
later streams until removal; `remove_stream` releases these resources as
resource_remove_otg_master_for_stream_output does. `dc_state(running)`
records each running stream's (`Modeset::{output, encoders}`), so streams
lit beside it take what it leaves. The start paths program what was
acquired (`DisplayPipes::encoders`): the DIO frontend and HDMI TMDS stream
encoder, 128b/132b SST training on the HPO DP link encoder and video on
the HPO DP stream encoder, and an MST stream's frontend or HPO stream,
SAT row and VC rate on its stream encoder (`MstPayload::stream`,
`Modeset::mst_stream_encoder`) with its link trained once on the link's
HPO DP link encoder, which stays the link's when the training stream
leaves and the link is handed to another stream's display
(`MstLink::displays` maps each payload's stream encoder to its head pipe).
FRL keeps its single HPO FRL encoder.

Deviations from Linux: the
primary takes the OTG master where amdgpu_dm's topmost plane does (the
pipe sets match; within a stream an overlay above the primary and the
primary trade pipes), planes of different CRTCs are added CRTC by CRTC
rather than interleaved by DRM's global zpos, and no SubVP phantom or
seamless-boot stream takes pipes (the firmware display is retired first).

**Audio.** Navi44 boards expose the same `1002:ab40` HDMI/DP audio function
(Linux `hda_intel.c` lists only `ab40` for RDNA4); runtime PM finds it as PCI
function 1 of the GPU without a device-id check.

**Not yet verified.** No Navi44, 9070 GRE or AI PRO R9700 board has run any
of this; Navi44's discovery is assumed to match Navi48 apart from the versions
above (one VCN5.0.0, DCN 4.0.1, MMHUB 4.1.0, OSSSYS 7.0.0, NBIF/NBIO, SMUIO
14.0.2, HDP 6.x), and any other discovered version fails closed.

### Selected RX 9000 userspace INFO requirements

Native Rust tests exercise the actual query, firmware metadata, owner readiness
and refusal paths. The production DRM3.0.0 and ACCEL_WORKING=0 gates remain.
The selected libdrm initializer rejects zero acceleration; Mesa's common query
path additionally requires DRM minor54. Internal tests and source audit do not
establish external userspace compatibility. Selected Mesa/libdrm must exercise
the real NARF ioctl/device boundary before application capability promotion.

### Navi 48 PCIe probe (RX 9070 XT)

The next discrete target is Navi48, selected from the September 2026
[Steam PC video-card survey](https://store.steampowered.com/hwsurvey/videocard/):
RX 9070 XT is the leading named AMD card at 1.42%. The larger generic
"AMD Radeon Graphics" entry does not identify a chip. This selection is a
dated snapshot, not a permanent popularity claim.

`1002:7550` binds as `Family::Navi4`, `asic="navi48"` (any RDNA4 board binds as
above). This ID also covers RX 9070/GRE; neither SKU nor enabled CU count is
inferred from it. Probe uses
the existing bounded PCIe discovery reader and total/visible VRAM accounting.
`DEV_INFO` requires exactly one GC0 12.0.0 or 12.0.1 discovery record and a GC topology
table, then reports `AMDGPU_FAMILY_GC_12_0_0` (152), eight hardware contexts,
and GMC12's 48-bit VA geometry. Shader geometry describes discovered maxima;
the active CU count, CU bitmap and enabled render-backend mask remain zero
until the cold-boot owner samples harvesting. `ACCEL_WORKING` remains zero.
What Mesa 26's ac_query_gpu_info cannot start without is answered too:
`FW_VERSION` reports ME, PFP and MEC `ucode_version` and v2.0
`ucode_feature_version` (`amdgpu_navi48_ucode::Image::feature`), published
by `prepare`. `FW_VCN` on VCN5.0.0 reports the common firmware header's raw
`ucode_version` with `feature=0`, as `amdgpu_firmware_info` does. The version
comes from the same retained GC12 container whose payload PSP accepted;
the header is container metadata, not a separate PSP-signed version claim.
The PSP owner retains it only after the complete GC12 upload succeeds and
exposes it only after boot completion with its TMR and VCN entry retained.
The platform publishes it beside media capabilities only when the current
client VCN transport has its native IB/interrupt proof and retained source
owner; a stopped diagnostic, failed/cancelled load or absent image grants
no query. Reset/suspend withdraw this media publication before their first
await, and recovery publishes only fresh proof. Missing publication and
other firmware types return EINVAL. This closes Mesa26.2.4's required VCN
firmware query when the unified ring is present; DRMminor and codec bits
remain unchanged. `READ_MMR_REG` answers soc24's
allow-list only for `GB_ADDR_CONFIG` (GC segment 0 + 0x13de, from the
topology sample's `gb_addr_config`), with Linux's SE (< 4) / SH (< 2) /
count (<= 128) checks and EFAULT for any other offset. `MAX_IBS` on an open
of a card with a submitter reports `Submitter::max_ibs` for each IP type it
runs (8 on Navi48, `MAX_JOB_IBS`) and 0 for the rest.
`DEV_INFO.gpu_counter_freq` is `Snapshot::reference_clock_10khz` times
ten (kHz), from `amdgpu_info::reference_clock_10khz(vbios, navi)`:
smu_info v3/v4 `core_refclk_10khz` (byte 16), replaced on Navi and later by
gfx_info v3.x/v2.2+ timer reference (byte 40), as
amdgpu_atomfirmware_get_clock_info; 0 without a VBIOS. This also applies to
the shared discrete RX 6000 reply on Navi21/22/23/24, independently of
acceleration opt-in or cold-boot publication.
`DEV_INFO.vram_type` / `vram_bit_width` are `Snapshot::{vram_type,
vram_bit_width}`, from `amdgpu_info::umc_vram(vbios)` on discrete Navi4
parts only (amdgpu_gmc_get_vram_info's GC 12.0.x arm): umc_info (master
data table 24) v4.0 `vram_type` (byte 26, mapped to `AMDGPU_VRAM_TYPE_*`)
and `channel_num << channel_width` (bytes 64, 65); 0 elsewhere. On Navi48,
`TIMESTAMP` returns SMUIO 14.0.2's GOLDEN_TSC counter
(`amdgpu_smuio14::ClockReader`, upper-lower-upper with a re-read when the
upper half moved), published at the topology stage; elsewhere EINVAL.

`unsafe amdgpu_gfx12_topology::read` requires exclusive GRBM selector ownership
and ready firmware/power. It validates GC12.0.0/12.0.1 banks and discovery dimensions,
combines fused and inherited software SA/WGP/RB disable masks, and restores
the previous GRBM selector on success and failure within one capability
invocation. It never changes harvesting masks. `Topology` reports active CUs,
shader arrays, enabled RBs and Linux's 4×4 CU bitmap packing (SE4–7 in columns
2/3). Cold boot publishes this inventory to `DEV_INFO` after initial power
setup; it does not advertise queues or acceleration.

When VFCT has no image, VBIOS acquisition supports the SMUIO14.0.2 ROM read
ports (`0xe4/0xe5`, base index zero) only with matching GC12.0.0/12.0.1 and NBIO7.7.0
or 7.7.1 discovery. The read preserves ROM_INDEX, checks PCI authority per
chunk and validates the image's PCI identity and ATOM directory. Duplicate,
unsupported or truncated banks are rejected before MMIO. Probe does not enable
PCI ROM decoding or use the legacy ROM-version-only fallback for Navi48.

Navi4 has no legacy single firmware image (`ChipInfo::fw_name` is empty).
Both legacy firmware loaders reject it before registry access. Existing GFX9/11,
MES11, GMC9/11, DCN2/3, backlight, APU SMU and VCN2–4 entry points refuse Navi4;
discrete suspend returns `NotImplemented` before changing power state. The
explicit PSP14 bootstrap below is the first firmware stage; SMU14,
GMC12/SDMA7 and DCN4 owners are still required for engine startup/modesetting.

### Navi 48 PSP14 secure-OS bootstrap

`amdgpu_psp_boot::Firmware::open` and `unsafe Bootloader::new` also accept
RDNA4 with exactly one GC0 12.0.0 or 12.0.1 and MP0 14.0.2 or 14.0.3. Discovery
selects `amdgpu/psp_14_0_2_sos.bin` or `amdgpu/psp_14_0_3_sos.bin`, and a kicker
board (`amdgpu_rdna4::is_kicker`) MP0 14.0.3's `psp_14_0_3_sos_kicker.bin`;
there is no revision fallback. `Firmware` and `Bootloader`
retain that target, rejecting a cross-target load before MMIO or state changes.

`amdgpu_psp_firmware::Image::parse_psp14` accepts the PSP14 v2.0 container:
36-byte header, bounded 16-byte descriptors before the payload, and payload-
relative component ranges. Duplicate/unknown IDs, overlap, truncation, empty
components, missing system/SOS and components beyond the 1 MiB staging limit
are rejected. TOC/RL ranges are validated but are not boot commands. v2.1
auxiliary-image selection and SPDM remain unsupported. Registry access and
the retained validated copy use the same capability checks as Navi22.

The owner uploads KDB → SPL → system → SoC → interface → hardware-debug →
RAS → IP-key-manager → SOS, omitting absent optional components. It uses
MPASP C2PMSG35/36/81 (`0x63/0x64/0x91`, MP0 bank zero), the aligned GPU staging
address in MiB, bounded asynchronous waits, and changing SOS heartbeat proof.
Failure and cancellation prevent replay and quarantine published memory.
An already running SOS is checked without upload. The caller must supply
exclusively owned, trained VRAM with correct GMC12 addresses and exclusions;
use `Plan::read_navi48` for this GPU's inventory. This explicit API does not
automatically claim the GPU, initialize its GPCOM/TMR, set `fw_loaded`, or
enable graphics/display engines. Those remain separate bring-up stages.

### Navi 48 PSP ring and GDDR6 training

`unsafe amdgpu_psp_ring::Psp::new_navi48` claims the physical GPU's PSP14
GPCOM ring after SOS and VRAM training. It requires GC12.0.0/12.0.1, MP0 14.0.2/3,
NBIO7.7.0/7.7.1 or NBIF6.3.1 and HDP6.0.0/6.0.1/6.1.0/6.1.1/6.4.0.
Every bank is unique and bounded before device access. GMC12's bank-zero
`0x1614/0x1615/0x15a7` fields validate GPU addresses against the BAR0-backed
pool. HDP uses the verified NBIO bank-two flush remap and MEMSIZE posting read;
HDP6 never receives HDP5's obsolete invalidate-register write.

`setup_tmr_navi48(&Firmware).await` requires the matching PSP14 revision's
validated SOS container and an embedded TOC. It submits LOAD_TOC, bounds the
returned size, reserves MiB-aligned trusted memory and submits SETUP_TMR with
separate GPU and physical addresses. Existing capability checks, fence matching,
bounded waits and quarantine on cancellation apply. Cross-generation firmware,
Phoenix DMUB loading and Navi22 graphics operations are rejected. The caller
must retain TMR and stop all firmware consumers before unsafe teardown.

`unsafe amdgpu_gddr6::Trainer::new_navi48` uses this same exact layout and
PSP14's C2PMSG35/36 long-training protocol. The exclusive-client and exchange-
reservation contract of the Navi22 trainer applies. Before sending the command,
it retains the bottom 32 MiB preimage in system memory; only acknowledged
completion permits restoration and HDP flush. Runtime policy can disable
training, and resident SOS skips it. Timeout, cancellation or revocation retains
the preimage without racing a possibly active PSP writer or allowing replay.
These are explicit ownership APIs; the Navi48 boot inventory below supplies
reservations, while automatic cold boot still requires a coordinated owner.

### Navi 48 graphics and media firmware

`amdgpu_navi48_firmware::Firmware::open(gpu, registry, MesMode)` prepares the
complete mandatory SMU14, SDMA7, GC12 PFP/ME/MEC, MES, IMU, RLC, VCN5 and DCN4
set through live registry/blob invocations. Names come from
`amdgpu_rdna4::FirmwareSet`: GC12.0.0/12.0.1, MP1 14.0.2/3 and SDMA7.0.0/1 each
select their own images, and a kicker board its RLC/IMU/SMU kicker builds. One
VCN5.0.0 and DCN4.0.1 (including raw 4.1.0 discovery encoding) are required. Separate and unified MES images are
explicit choices; missing or invalid files never fall back to another GPU.

`amdgpu_navi48_ucode::Image::parse` validates each IP/header version, complete
container, aligned bounded nonoverlapping instruction/data regions, RLC
metadata and entry points. RS64 instruction and stack images are separate;
PFP/ME each upload two stack copies, MEC four. IMU offsets are payload-relative;
CP/MES offsets are file-relative. VCN uploads its complete signed payload;
DMCUB uploads only signed instructions. SMU's trailing PowerPlay metadata stays
separate. `entry_points()` retains 64-bit CP/MES code/data addresses for queue
bring-up. Structural parsing does not authenticate firmware.

`Psp::load_smc_navi48` loads the prepared SMU once after TMR setup. The owner
must complete the SMU board-power stages and stop DMUB before
`load_gfx_navi48`. The ring captures the GPU's firmware IP target at construction
and rejects mismatched sets before upload. Graphics uploads follow Linux's
UCODE_ID order: SDMA, RS64 instructions/stacks, MES pipes, IMU, RLC lists and
IRAM/DRAM, RLC_G, AUTOLOAD_RLC, then VCN/DMCUB. Media entry points must be aligned
and within the retained TMR. `wait_gfx_boot_navi48` checks CP idle and GC12's
bank-one RLC status at `0x4e7c`. Cancellation preserves the in-flight payload,
ring and TMR and prevents replay. Successful autoload does not initialize
VMs, interrupts or command queues and does not publish `fw_loaded`.

### Navi 48 boot memory and SMU14 power control

`unsafe amdgpu_vram_boot::Plan::read_navi48` inventories the complete GMC12
VRAM aperture against DCN4's address translation and the reported physical
size. It uses four DCN4 scanout/cursor register windows, including 16-bit pitch
and viewport-start fields, and rejects enabled contexts in GC12/MMHUB4.1.
Packed linear RGB surfaces are supported; tiled, compressed, protected, YUV or
VM surfaces reject the inventory. Firmware/ATOM, discovery tail, runtime DB,
training exchanges, inherited DMUB windows (including DCN4 Region6 shared
state), boot framebuffer and explicit other clients remain protected before
CPU-visible BAR clipping. `into_pool` retains the existing unsafe exclusive-
client contract. The inventory performs no hardware writes.

`unsafe amdgpu_smu_navi48::Smu::after_upload(gpu, pci_cap, pool)` requires
successfully loaded SMU14 firmware, trained VRAM, retained PSP/TMR and exclusive
MP1/index/HDP/reset/power ownership. It validates the exact MP1 14.0.2/3 bank-one
mailbox (`0x82/0x92/0x9a`) and the GMC12/BAR0 pool mapping, then reserves a
16 KiB transfer buffer without publishing it. `verify().await` requires driver
interface `0x2e` and a nonzero firmware version.

`read_board().await` obtains TABLE_COMBO_PPTABLE from the running SMU. It checks
SCPM policy, zeroes/flushed staging, publishes the GPU address, awaits transfer
completion and validates the 5812-byte format-23 combo's subtable bounds.
`upload_board().await` sends only its unmodified 4468-byte PPTable to
TABLE_PPTABLE. The combined driver's 1344-byte prefix is never sent as power
settings. Board information comes from this GPU's running firmware; no
Navi22 table layout, reference-board replacement or overdrive is used.

After graphics/RLC boot, `configure_power().await` runs DC BTC, installs a
board-supported mask for GFX DPM, autonomous thermal/fan/electrical
protection and BACO (FEATURE_BACO_BIT 19, which runtime PM needs and Linux
always allows), enables it and verifies the running mask and GFX frequency
range.
Boot display/memory/link clocks and automatic gating remain excluded until
native DCN owns their constraints. The owner publishes `PowerStatus` only
after the whole sequence succeeds. Each operation is single-attempt; timeout,
cancellation, revocation or an unknown reply prevents reuse. Incomplete SMU
DMA retains its published buffer. Acknowledged transfer completion alone
permits reclaiming that buffer. All waits use scheduler time futures, with
capability revalidation at every command/read/copy chunk.

The internal `Smu::enable_display_power` transition extends the verified mask
only with UCLK/FCLK/SOCCLK/DCN DPM (bits 3/4/5/7). The board must support all
four; SCPM is checked again and required autonomous protections must remain
enabled. Voltage scaling, deep sleep, link DPM, DF C-states and GFXOFF stay
excluded. It requires retired display consumers and idle engines. Success
publishes the new `PowerStatus`; partial failure/cancellation retains the
owner and prevents replay. Only the retained DCN4 clock owner initiates this
transition, after checking every display consumer. With UCLK DPM running it
also reads the UCLK range (GetMin/MaxDpmFreq of PPCLK_UCLK, `2 << 16`) into
`PowerStatus::uclk_mhz`, which `configure_power` leaves `None`.

Each successful `Smu::configure_power` / `enable_display_power` publishes
DEV_INFO's clocks (`amdgpu_info::publish_navi48_clocks`, from
`smu::dev_info_clocks`, kHz): min/max engine clock from the GFXCLK DPM range;
min/max memory clock from `uclk_mhz`, or, while UCLK DPM is off, both from
the VBIOS boot UCLK (`amdgpu_info::boot_mclk_10khz`, firmware_info v3 byte
12, as smu_v14_0_get_vbios_bootup_values; 0 without one). Other parts report
zero clocks.

`read_board` also decodes optional board `Limits` from the combo, following
Linux `smu_v14_0_2_get_thermal_temperature_range`: CustomSkuTable
`TemperatureLimit` for edge/hotspot/memory (critical) and that limit plus
`CTF_OFFSET` 5 °C (emergency), powerplay `software_shutdown_temp` with the
fan-abnormal offset, `FanMaximumRpm` when `FeaturesToRun` has FAN_CONTROL,
and the AC PPT0 default. A zero or implausible temperature limit yields no
limits instead of failing boot. `configure_power` records which autonomous
protections (THROTTLERS, GTHR, ACDC, VR0HOT, FW_CTF, FAN_CONTROL,
FAN_ABNORMAL) are running; `protected(enabled)` checks a later mask still
contains all of them. No narf path disables a protection feature.

`read_telemetry().await` requires configured power and mirrors Linux
`smu_cmn_get_metrics_table`: it zeroes and flushes the staging buffer,
transfers TABLE_SMU_METRICS (5) to VRAM, decodes `SmuMetrics_t`
(`get_smu_metrics_data`: temperatures in millidegrees, busy-threshold GFX/FCLK/
UCLK averages, `smu_safe_u16_nn` activity, fan PWM percent scaled to 0–255,
socket/board watts, VDDGFX mV, current clocks, and a throttler bit per nonzero
`ThrottlingPercentage`), then reads the running feature mask and
`GetPptLimit` for the AC source. `set_gfx_level(Auto|Low|High)` issues only
GFXCLK `SetSoftMaxByFreq` then `SetSoftMinByFreq`, as Linux
`smu_v14_0_set_performance_level` does for GFXCLK (automatic `0xffff`/0
bounds, `SMU_V14_SOFT_FREQ_ROUND` on manual maxima); display, memory and
fabric clocks keep their pinned floors. Runtime commands run from
`PowerReady`/`DisplayPowerReady` through a transient `Runtime` state: a clean
PMFW rejection restores the previous state as in Linux, while timeout,
revocation, device loss or cancellation leave the owner unusable.

`unsafe deep_sleep_control().await` is `smu_v14_0_deep_sleep_control(true)`
as SMU 14.0.2 maps it: for each DS feature of Linux's walk the board supports
(FeaturesToRun), in Linux's order DS_GFXCLK, DS_UCLK, DS_FCLK, DS_SOCCLK,
DS_LCLK, EnableSmuFeaturesLow/High of that bit (sent again when already
running, as Linux does). DS_VCN, the walk's last bit, is left out because the
static media policy requires it off, and DS_MP0CLK/DS_MP1CLK have no 14.0.2
bit. Narf's boot allowed only a restricted mask, so the walk's bits are first
added to the allowed mask (SetAllowedFeaturesMaskHigh/Low). It runs only
after the display power transition. The first PMFW refusal ends the walk and
is returned in `DeepSleep::refused` (`DeepSleepRefused { feature, error }`)
with the owner reusable, as Linux logs and returns it and its caller ignores
it. Every recorded protection and display DPM bit must still run afterwards,
or the owner fails; transport failures are terminal, as for every runtime
command. Linux runs it from `smu_v14_0_2_set_power_profile_mode`
(`smu_bump_power_profile_mode` at COMPLETE_INIT and on every profile
change), and with `PP_SMC_POWER_PROFILE_COMPUTE` in the workload mask it
disables deep sleep instead. Navi48 in narf has no power-profile path (no
`pp_power_profile_mode`, no KFD compute profile), so the bootup default
profile, which is not COMPUTE, is the only one: the display owner runs the
enable once, right after the DCN4 clock owner started (narf turns display DPM
on only then) and offered PMFW the watermark ranges
(`ColdBoot::start_display_clocks`, below). A board whose display clocks never
start keeps deep sleep off. DS_DCFCLK and GFX_ULV, which Linux's
EnableAllSmuFeatures turns on at boot outside this walk, stay off.

After a successful retained boot, `amdgpu_navi48_platform::run` starts
`amdgpu_navi48_power`. Through the shared `amdgpu_hwmon` it publishes `/sys/class/hwmon/hwmon<N>` (first free N)
named `amdgpu` and spawns a monitor that refreshes telemetry every second,
holding the platform owner only for each refresh, like Linux's cached metrics
table. Attributes follow Linux amdgpu_pm.c for an SMU14.0.2 dGPU: `temp1..3`
(edge/junction/mem) `_input/_label/_crit/_crit_hyst` (-273150)/`_emergency`;
with PMFW fan control, read-only `pwm1` (0–255), `pwm1_enable` 2 (automatic),
`pwm1_min/max`, `fan1_input/min/max`; `in0` (vddgfx, mV); `power1_average`,
`power1_cap` and `power1_cap_default` in µW labelled PPT; `freq1` (sclk) and
`freq2` (mclk) in Hz. Linux's smu_v14_0_2 provides no fan-mode or PWM setter,
so fan control stays automatic. `power1_cap` is writable as
amdgpu_hwmon_set_power_cap (decimal µW, truncated to W) and accepts only
smu_v14_0_2_init_ppt_limits' non-overdrive AC range, reported by
`power1_cap_min`/`power1_cap_max` (`Limits::{ppt_min_w, ppt_max_w}`: socket
and message limits, the minimum lowered by the overdrive minimum percentage
when the board supports PPT overdrive); out-of-range writes are EINVAL. The
store validates synchronously and `amdgpu_navi48_platform::set_power_cap(w)`
applies SetPptLimit (0x32) on the executor, which needs the PPT feature
(FEATURE_THROTTLERS_BIT); the next sample's GetPptLimit is what `power1_cap`
reads. `amdgpu_hwmon::publish_writable` adds writable attributes to the shared
hwmon node. `power1_input` is absent. Values read empty
until a sample or board limit exists, never as a fake zero. The monitor logs
throttlers starting and ending, loss of a recorded protection, the first
failed refresh, and hotspot reaching `software_shutdown_temp`. A fresh
successful sample at that threshold requests the existing orderly hardware-
protection shutdown (`hw_protection_shutdown`, 10 s filesystem-sync budget
and its independent forced fallback). The decision runs synchronously under
the same platform owner that produced the reading, so reset/PM cannot publish
a successor between generation validation and notification. Only the first
trip per hot episode notifies; a fresh below-threshold reading ends that
episode, while missing data or an owner change does not. Cached telemetry
remains useful for hwmon but never fabricates a fresh trip. A clean PMFW
rejection keeps polling; a terminal SMU failure stops the monitor. Platform diagnostics carry the latest
snapshot. The DRM card's `power_dpm_force_performance_level` accepts native
RX 9000 `auto|low|high` through `amdgpu_navi48_power::request_level` and
`amdgpu_navi48_platform::set_gfx_level`; listed Navi48/Navi44 cards and the
exact discovery-supported OEM controller use the same owner. The parser
rejects unsupported Linux manual/profile levels with EOPNOTSUPP and malformed
values with EINVAL. Synchronous stores validate and enqueue; a normal async
mutex serializes changes, and a newer pending write supersedes an older one.
Queued writes recheck their owner generation under OWNER after runtime-PM
access and before any SMU write, so reset/suspend successors reject stale
requests. Reads report the last successfully applied level (initially `auto`),
updated synchronously under OWNER only after both GFXCLK bounds succeed;
rejected or cancelled changes never publish the requested level. Display,
memory and fabric floors remain with their existing admission owners.
Other power-policy feature-mask controls are unchanged.

`amdgpu_navi48_power::thermal` retains THM/MP1 interrupt-register ownership
in the independent IH service. Native THM14.0.2/3 bank0 and MP1 bank1 are
resolved and bounded from discovery; without that layout or a nonzero board
software-shutdown limit, no OS source is armed and telemetry remains the
fallback. Before CPU MSI delivery, the retained controller programs
smu_v14_0_set_irq_state's MAX_IH_CREDIT5, IH_HW_ENA, low0/high
min(255, software_shutdown_temp), INTH/INTL/TRIGGER unmask and source clears,
then MP1 ID0xfe/VALID0 and its interrupt unmask. The asynchronous cold-boot
interrupt handoff sends `AllowIHHostInterrupt` (0x4d) only after that IH/thermal
owner is retained; cancellation leaves the SMU runtime command owned and
non-retryable. A returned failure stops the service and fails the handoff.

Exact THM sources0/1 count high/low events; THM has no guessed per-vector ACK.
A high alert coalesces one owner-bound confirmation task with Linux's50 ms
SW CTF delay. It reads a fresh hotspot under the platform owner. Confirmed
below-threshold data dismisses the alert; unreadable data after a known high
IRQ requests shutdown as smu_swctf_delayed_work_handler does. Reset/PM cancels
the old pending claim and generation, and an old task cannot clear a new
owner's claim or request shutdown from its stale sample. MP1 source0xfe
alone receives INT_ACK, before its context is handled. Fan-abnormal context8
lowers the IRQ threshold by the signed board offset, clamped to0..255;
fan-recovery9 restores the board threshold, clearing TRIGGER_MASK as Linux
does. Other MP1 contexts are acknowledged and counted without invented
policy; foreign sources are untouched. `interrupts::Status::thermal` reports
arming, thresholds, counters and failures. Service retirement masks THM and
MP1 sources before CPU routing is withdrawn. PMFW automatic fan control and
hardware CTF remain enabled. All behavior is reference/model-tested only.

`unsafe amdgpu_dcn401_clk::ClockManager::new` prepares a separate DAL mailbox
owner without hardware writes. Exact Navi48/GC12/MP1 14.0.2/3/DCN4.0.1 discovery
is required (the native DCN4.1.0 discovery spelling is also accepted). MP1 bank
one must agree with Linux's absolute DAL registers `0x1628a/0x16273/0x16274`;
PPSMC registers and message IDs are never reused. DCN banks two and three bound
all four OTGs, legacy streams, HPO DP streams/link clocks and the single FRL
stream. An active or disappearing consumer rejects startup/clock programming
before any power future is polled or DAL command written. OTG retirement
requires both the requested and current master-enable bits clear, as well as
`OTG_BUSY`; an unacknowledged disable is still a live consumer.

`unsafe start(&mut Smu).await` enables the restricted display power policy,
checks nonzero firmware and DAL driver/header versions 1, and queries native
SOCCLK/UCLK/FCLK/DISPCLK/DPPCLK/DCFCLK/DTBCLK levels. Fine-grained clocks read two
endpoints; discrete tables are bounded to eight entries (six for UCLK), with
nonzero ordered MHz values. These become immutable `Levels` only after the
entire handshake succeeds. DPREFCLK remains firmware-owned.
One-level ranges describe fixed clocks; they satisfy admitted requests without
issuing unsupported DPM-floor or UCLK-switch commands.

`prepare(Request).await` accepts 1–4 displays and bounded, nonzero DISP/DPP/DTB
rates in kHz. Every consumer must remain retired. It reports the display count
(a refusal ignored, below), pins DCFCLK and UCLK to the reported maxima, disables UCLK switching, and sets
the requested display clocks, rounding mailbox requests up to MHz.
`Request::deep_sleep_dcfclk_khz` (DPMM's deep-sleep DCFCLK, zero for none)
is sent as SetMinDeepSleepDcfclk (0xd) when DCFCLK has DPM. Each floor
requires both mailbox acceptance and the corresponding bit from
`ReturnHardMinStatus`; its one-second deadline includes nested mailbox waits.
DISP/DPP/DTB replies are actual kHz, checked against the requested floor and
firmware ceiling. `Applied` distinguishes those actual rates from acknowledged
DCF/UCLK floor requests. FCLK follows DCFCLK on this ASIC; the unsupported
FCLK-switch message is not sent. This is the pre-modeset policy; live
changes go through `update_live` (below).

`update_live(regs, Request, safe_to_lower, held, dto).await` is
dcn401_update_clocks while displays run (their consumer registers `held`):
in prepare_bandwidth (`safe_to_lower` false) it sends the display count and
only raises clocks, in optimize_bandwidth (true) it also lowers them
(`should_set_clock`). DTBCLK first, then DISPCLK; a lowered DPPCLK has the
DPP DTOs set for the new reference (`dto`) before the reference falls and
again for the actual one after, a raised one is raised before the DTOs are
updated. DENTIST stays PMFW's. A failed `dto` step is `Error::Dto`; failure
or cancellation leaves the owner failed.

`update_bandwidth(regs, Bandwidth, safe_to_lower, held).await` is
dcn401_build_update_bandwidth_clocks_sequence while displays run. `Bandwidth
{ uclk_pstate, fclk_pstate, dramclk_khz, idle_dramclk_khz, fclk_khz,
idle_fclk_khz, deep_sleep_dcfclk_khz }` is DC's `clk` state
(`Bandwidth::pinned(&Levels)`: no switching, UCLK and FCLK at their maxima;
`Status::bandwidth` the running one, dcn401_init_clocks' P-state support
set before the first prepare). `Status::uclk_switching()` is true only once
a bandwidth sequence this owner ran since its first `prepare` allowed
switching (`applied` present and `bandwidth.uclk_pstate`): the initial
P-state support is DC's software state, never sent to PMFW, so a fresh
owner (cold boot, S3 or runtime resume) has nothing to pin, and its first
`prepare` disallows switching itself as Linux's first prepare_bandwidth
does. In Linux's order: SetUclkPstateAllow(1)
(0x1a) before the floors when switching is gained, which only
optimize_bandwidth may do (`should_update_pstate_support`); with idle DPM
(`Layout::chip` Navi48, PMFW 0x681800 or later, UCLK and FCLK with more than
one level) the active and idle UCLK/FCLK floor pairs (0x18, 0x19), otherwise
the UCLK hard minimum; SetUclkPstateAllow(0) after the floors when
switching is lost; the deep-sleep DCFCLK first. Each floor obeys
`should_set_clock`; FCLK has no switch message on this ASIC. `prepare`
routes its UCLK step through the same sequence with `Bandwidth::pinned`.
`Applied::uclk_pstate` and `memory_floor_khz` (the active UCLK floor) are
what display deadlines bind against. As in Linux, whose dcn401_smu_* helpers
return nothing the clock manager reads, a PMFW refusal of any of these
messages, or a UCLK floor ReturnHardMinStatus does not acknowledge within a
second, is logged and counted in `Status::ignored` (`Ignored { count, last
}`) and the sequence goes on. NumOfDisplays (0xe) and SetMinDeepSleepDcfclk
(0xd), in `prepare` and `update_live` as in the bandwidth sequence, are
ignored the same way (dcn401_smu_set_num_of_displays and
dcn401_smu_set_min_deep_sleep_dcef_clk return nothing). Every message, as
dcn401_smu_send_msg_with_param, first waits only for DAL_RESP to be nonzero
(any value: an OK, or a refusal this or an earlier owner left there) and
then sends; only PMFW's answer to the message sent can be a refusal, so a
message never sent is never counted. A sent ignored-result message's response
timeout is also logged and counted; after another bounded readiness wait,
a later command may replace that known unanswered transaction, as Linux does.
An unknown inherited busy mailbox still fails before any write. Queries and
display-frequency commands require their response; revocation, device loss,
required-result failure and cancellation leave the owner unusable.

`notify_wm_ranges(regs, address).await` is dcn401_notify_wm_ranges:
SetDalDramAddrHigh/Low (5, 6) with the GPU address of
`ClockManager::wm_range_table()` (`WatermarksExternal_t`, 112 bytes: set A
`WATERMARKS_CLOCK_RANGE`, set 1A `WATERMARKS_DUMMY_PSTATE`), then
TransferTableDram2Smu (8) of TABLE_WATERMARKS (2), each refusal or sent timeout
ignored and logged the same way. The owner stays `Applying` throughout the
sequence and on cancellation; a transport/authority failure enters `Failed`,
so a partially sent watermark sequence cannot be reused.

`release(regs).await` is dcn401_update_clocks' optimize once no stream is
left (NumOfDisplays 0, DCFCLK, UCLK and FCLK at their lowest levels, UCLK
switching allowed; see "No display left" under Navi 48 UCLK P-state
switching). It needs an `Applied` owner with every consumer retired and
runs once per configuration.

`Starting`/`Applying` are set before awaits. Failure records `Failed(Error)`;
cancellation leaves the in-flight state. Both prevent mailbox replay, and
partial floors are not rolled back. Historical successful levels/applied state
remain diagnostic. `ColdBoot::prepare_display_clocks` and its platform wrapper
serialize both MP1 owners after the three kernel queue proofs have drained;
`display_clock_status`/platform `display_clocks` expose retained progress.
The clocks are not changed automatically during firmware boot. Stream retirement,
mode bandwidth math, link and scanout setup remain prerequisites to native
modesetting.

`unsafe amdgpu_dcn401_dccg::Dccg::new` retains the native four-pipe DCCG owner
without register writes. It checks the same display discovery and consumer
bounds, DCN bank one through `DPPCLK_CTRL`, and the native read-only PLL/DPREF
aperture. `prepare(&mut ClockManager, Request).await` requires a matching BAR,
current acknowledged global clocks and all 51 display consumer checks clear.
`Request` selects a pipe, DPP kHz and disabled, DisplayPort, FRL or TMDS clocks.
Out-of-range pipes/rates, zero active clocks and oversized DTO ratios fail
before writes. DPP uses ceil(255 × pipe/global) and the native enable field in
`DPPCLK_CTRL` (three bits per pipe); the older DTO-enable layout is not used.

DP pixel DTOs derive DPREFCLK from native PLL multiplier and DFS divider
readback with no guessed fallback. FRL uses acknowledged DTBCLK. Both program
an integer plus fractional Hz ratio, source mux and required clock gates,
preserving neighboring fields. TMDS disables DP DTO and selects divide-by-two
or four. Changed TMDS dividers retrigger DENTIST and await its completion with
a 100 ms bound, following the native DIG FIFO workaround. This does not
program an HDMI PLL or turn on transmission.
Disabled pipes park their DPP and pixel clocks; shared root gates remain on.

Readback verifies every programmed field. Partial failure records a terminal
`Failed(Error)`; cancellation leaves `Applying`. Neither can replay, and
historical successful `Applied` entries remain tagged with their global clock
snapshot. No stream may use a stale snapshot after global clocks change:
`Dccg::update_dpp_dtos(regs, ref_khz, &[(pipe, dpp_khz)], safe_to_lower)` is
dcn401_update_clocks_update_dpp_dto for live pipes (dccg401_update_dpp_dto's
phase where the DPPCLK rises, or every one when safe to lower) and
`rebind_global(old, new)` moves the pipe records to the new global clocks;
`prepare_except(clocks, request, held)` programs a pipe beside another
display's running consumers.
`ColdBoot::prepare_display_pipe_clocks` and the platform wrapper serialize the
matching owners after drained engine proofs. `display_pipe_clock_status` and
platform diagnostics expose progress. An uncertain DCCG transition also blocks
subsequent platform global-clock changes.

`Dccg::route_stream(&mut ClockManager, StreamRoute)` connects one of four HPO
DP stream clocks or the single FRL stream clock to a prepared pixel pipe;
`pipe: None` parks that stream on REFCLK. DP and FRL require matching pixel
signal types and the same current acknowledged global-clock snapshot. Divider,
source mux and enable readback (including current DPREFCLK for DP) must still
match the prepared pipe. A mismatch is terminal before any routing writes.
Routes preserve other stream fields and never change the DTO reference source.
Every stream remains retired; this does not enable a PHY, encoder or video FIFO.

Before reprogramming a pixel DTO, the owner reads all actual stream-clock muxes
and parks every route selecting that pipe, including inherited routes without
software history. Unrelated routes remain intact. Successful parking/routing
is retained in `Status::routes`; partial failures share the terminal DCCG state.
`ColdBoot::route_display_stream_clock` and the platform async wrapper serialize
this operation with clock and engine owners after drained kernel proofs.

`unsafe amdgpu_dcn401_otg::Otg::new` prepares the four native timing generators
without MMIO writes. It requires the same native discovery, permanent mappings
and exclusive display/PM/reset ownership; firmware/FAMS timing writers must be
excluded. `prepare(&mut ClockManager, &mut Dccg, Request).await` programs disabled
progressive timing with fixed refresh and one OPP per OTG. HDMI TMDS and FRL
also accept YCbCr 4:2:0: horizontal boundaries must be even and active width
must fit the 4096-pixel formatter buffer. The OTG divides horizontal timing
by two and selects 4:2:0 data format. Interlace and VRR are not
represented by this request (ODM combine is `Request::odm`, see Navi 48
display admission); a live scanout's DRR is `Otg::set_drr` (Navi 48
variable refresh). `GlobalSync` supplies
validated DLG field values (startup/keepout in lines; update/ready in pixels),
not a bandwidth proof. Totals, porches, sync widths, blanking minima and every
native field width are checked before writes. Zero vertical front porch is
rejected instead of silently changing the sink's timing.

Preparation requires matching BAR owners, current acknowledged global clocks,
the prepared pipe's signal/frequency, and live divider readback. TMDS verifies
its DPP/DTO-disable/divider state; its PHY PLL remains a separate prerequisite.
All display consumers must be retired, and the target must have no outstanding
master-update lock or soft reset. Native ODM/OTG clocks each require hardware
acknowledgement within 1 ms. Programming establishes ODM bypass, equal fixed
vertical totals, sync polarity, global-sync/PSTATE keepout and VTG parameters;
VTG and OTG stay disabled. Odd horizontal boundaries select manual no-divide.
Both HPO DP and FRL use native output mux 2; mux 1 is reserved. No legacy ODM
segment-width registers are programmed. Every changed field is read back.

`unsafe retire(pipe).await` requires stopped CPU writers and retained scanout
surfaces, page tables, HUBP and OPP resources. It first checks that all legacy,
HPO DP and FRL streams/link clocks are retired. It disconnects all ODM segments,
clears combining-memory selection, requests OTG disable and disables VTG, then
waits independently for current master state and busy to clear (150 ms each).
Once both clear, it restores `OTG_OUT_MUX` to DIO with readback, including
UHBR/FRL routes. A failed disable leaves the mux unchanged; a failed mux reset
cannot publish retirement. Clocks remain on. This proves timing retirement only; it cannot authorize memory
reuse or replace HUBP fetch retirement. Uncertain writes, timeouts or revocation
record `Failed`; cancellation retains `Preparing(pipe)`/`Retiring(pipe)`. Those
states block replay and platform clock changes. `Status::pipes` is historical
programming tagged with its clock snapshot; changing clocks invalidates it.

`ColdBoot::prepare_display_timing`/`unsafe retire_display_timing` and matching
platform wrappers serialize these operations after the drained kernel proofs.
`display_timing_status`/platform `display_timing` report retained state. None of
these operations runs automatically during boot. Plane setup, bandwidth and
watermarks, link/PHY programming and surface scanout enable remain required.

The same timing owner also exposes
`prepare_blank(&mut ClockManager, &mut Dccg, BlankRequest).await` for native
OPP/FMT/DPG preparation. `BlankRequest` selects a prepared pipe and RGB
`ColorDepth::{Bpc8,Bpc10,Bpc12}`; output is full range. The recorded timing must
match current readback-checked pipe clocks and fit the DPG's 14-bit active
dimensions. All consumers remain retired. Inherited digital bypass, pending
FMT/DPG updates and timing locks reject the request before writes.

Native OPP clock-on acknowledgement is bounded to 1 ms. The formatter disables
chroma subsampling and dithering, sets 8-bit truncation or native rounded 10-bit
reduction (none at 12 bits), clears inherited RGB/YUV offsets in the shared
dither-seed registers, and programs full-range clamping and dynamic expansion.
DPG stages equal black color values with the prepared active dimensions,
zero offset and the selected component depth. Every field is read back.
`BlankApplied::pending` captures DPG's double-buffer state; it is diagnostic,
not proof that blanking is active. Native blank completion is checked
after timing enable by `start_blank`. `PreparingBlank(pipe)`/failure block replay and
platform clock changes; `BlankPrepared` records only successful staging in
`Status::blanks`. Reprogramming or retiring a pipe clears its staged record.
`ColdBoot::prepare_display_blank` and the matching platform wrapper retain the
same clock/PM/timing ownership. They do not enable timing, a plane or a link.

`unsafe start_blank(&mut ClockManager, &mut Dccg, pipe).await` starts that
prepared internal black pattern on one OTG. It requires stopped CPU scanout
writers, exclusive fetcher/cursor/metadata ownership and retention of all
associated surfaces, page tables, HUBP and OPP resources, including inherited
ones. All other timing generators and every external stream/link clock must
remain stopped. Each powered HUBP must positively acknowledge no outstanding
requests, with blank asserted, soft reset clear, fetch clock and cursor disabled,
and no enabled/queued dynamic-metadata, enabled 3D-LUT fetch or MALL prefetch
mode. TTU-disable may
be clear: native DCN401 uses `hubp2_set_blank_regs`, not `hubp1_disconnect`.
An already powered-off HUBP instead requires a power-gate request with force-on
clear and PGFSM OFF acknowledgement; its inaccessible registers are skipped.
Transitional/contradictory power states and zero HUBP reads without power-off
evidence do not satisfy these conditions. Startup itself does not retire planes;
it returns `Busy` when those prerequisites are absent.

Startup verifies matching retained timing/blank snapshots, current native DTO
clocks and live timing/OPP/formatter programming. TMDS returns `Unsupported`
until a native PHY PLL owner exists. Native sequencing selects the OPP, enables
VTG first (the DCN401 workaround), then enables OTG at disable point 2. Success
requires current-master acknowledgement, cleared DPG and FMT double-buffer
pending bits, and a subsequent fresh 24-bit frame-counter transition (including
wrap). One shared deadline allows three frame periods plus 5 ms; modes requiring
more than 1 second are rejected before writes. Final readback rechecks the black
pattern, timing, stopped fetchers and external consumers.

`BlankRunning` records the staged pattern and two observed frame counts in
`Status::running_blank`. `RunningBlank(pipe)` blocks preparation and platform
clock changes until acknowledged `retire(pipe)` clears that record. Only the
running pipe can be retired in this state. Failure records `Failed`; cancellation
retains `StartingBlank(pipe)`, preventing replay and ordinary retirement until
independent reset. No outcome releases scanout allocations. Successful internal
blank timing proves neither physical link output nor plane/bandwidth readiness.
`unsafe ColdBoot::start_display_blank` and its platform wrapper preserve the same
ownership and require the drained GC12/SDMA interrupt proofs; startup remains an
explicit operation, not part of boot's framebuffer handoff.

`unsafe Otg::retire_planes().await` disconnects all four MPC outputs and MPCCs,
including inherited cross-routes and blending trees, under the timing owner's
exclusive display/clock/PM lifetime. The constructor validates native MPC bank 3
through output mux 3; it still writes nothing. Callers must stop CPU scanout
writers, exclude firmware/FAMS and every surface/cursor/metadata/LUT, MPC, power
and timing writer, and retain all associated allocations and translations.
External streams/link clocks must already be stopped; timing may remain running
to latch disconnection. Active update locks, pending flips, GSL synchronization,
MALL prefetch mode, metadata/LUT loads and uncertain power states reject before
writes. This path does not abort those independent transactions.

The MPC retains all four physical MPCCs after pipe harvesting. When no sibling
display holds staged or live pipes, retirement resets every physical MPCC's
top/bottom/OPP/update-lock selector and MPC output mux (Linux's
`dcn10_init_pipes` / `mpc1_mpc_init` contract) and reads the selectors back.
MPCC drain waits remain limited to the unfused pool's pipes; Linux's
initialization does not wait for a fused pipe's MPCC status. An inherited
pending MPCC update or foreign selector rejects before writes. This sweep never touches the fused pipe's HUBP, DPP, OPP
or OTG block, and its report still covers only the unfused HUBPs. With a sibling
owner retained, only unowned pool pipes are inspected and disconnected; no
physical MPCC initialization is attempted outside that set.

Retirement parks output muxes first, then every MPCC top/bottom/OPP/update-lock
selector, and disables cursors on powered HUBPs. A shared 100 ms deadline bounds
all drain waits. Each unfused pipe's MPCC must acknowledge IDLE or DISABLED
with BUSY clear;
every powered HUBP must acknowledge no outstanding requests before any blanking
or clock gating. Native HUBP blanking asserts blank and clears TTU-disable;
MALL selection and surface GSL are cleared. Drain is checked again before fetch
clocks are disabled, followed by final power/route/lock/consumer readback.
Already-off HUBPs are identified through native DOMAIN0–3 PGFSM state and are
never accessed. No power domain is changed and DPP clocks/timing stay retained.

`PlanesRetired::{blanked,powered_off}` reports the two HUBP masks in
`Status::planes_retired`. Success enters `PlanesRetired`, allowing subsequent
timing/clock preparation subject to their live checks. This snapshot never
grants allocation reuse and proves nothing about GPUVM, writeback or other
engines. Cancellation retains `RetiringPlanes`; errors after writes enter
`Failed`, blocking replay, timing retirement and clock changes until independent
reset. `RunningBlank` must first retire its timing before plane retirement.
`unsafe ColdBoot::retire_display_planes` and the matching platform wrapper
serialize the operation after drained GC12/SDMA proofs. No automatic firmware
display takeover or visible link output is introduced.

`unsafe Otg::set_hubp_power(pipe, powered).await` owns native DOMAIN0–3
power transitions. All four MPC trees must be detached and acknowledge idle
or disabled; all timing and external consumers must be stopped. Powered HUBPs
must freshly prove blank, drained, clock-disabled and free of pending flips,
update/GSL locks, reset, cursor or auxiliary fetch activity. Off domains require
matching gate request and PGFSM acknowledgement; their registers are inaccessible.
The operation rejects uncertain inherited state before changing hardware.

The native bank-2 `DC_IP_REQUEST_CNTL` request brackets the PG_CONFIG write and
1 ms PGFSM wait, preserving its prior request state. The native full PG_CONFIG
write clears FORCEON. Power-on first acknowledges accessibility, rejects
unexpected active transactions, enables the fetch clock, waits for drain,
asserts native blank with TTU-disable clear, clears MALL/GSL and disables the
fetch clock again. Drain waits are bounded to 100 ms each; power-off requires
fresh stopped-fetcher evidence before requesting gating. Final checks cover
every route, consumer and domain. Repeating an acknowledged state is read-only.
No hardware reset, surface, VM, bandwidth, DPP or scanout setup is implied.

`HubpPower { pipe, powered }` is recorded in `Status::hubp_power[pipe]` as
historical evidence only. Success enters reusable `HubpPowerChanged`; subsequent
operations still check live state. A transition invalidates the old selected
power report and plane-retirement snapshot. Cancellation retains
`ChangingHubpPower(pipe)`; an error enters `Failed`, blocking replay and clock
changes. Neither outcome attempts speculative rollback. Callers exclude
firmware/FAMS and concurrent display/clock/power writers and retain all memory
and translations even after successful power-off. The matching
`unsafe ColdBoot::set_display_hubp_power` and platform wrapper serialize this
under the retained owner after the kernel engine proofs.

`unsafe Otg::prepare_surface(pool, SurfaceRequest).await` stages one retained
linear framebuffer per HUBP. The pool must belong to this GPU's correctly mapped,
exclusively owned VRAM; the matching ColdBoot/platform
`prepare_display_surface` wrappers use the boot owner's validated pool after
the kernel engine proofs. Requests select pipe 0–3, nonzero 14-bit dimensions
and a packed single-plane `SurfaceFormat`: X/A RGB and BGR 8888 and 2101010,
`Rgb565`, and X/A RGB and BGR 16161616F (`ALL`, `fourcc`/`from_fourcc`,
`bytes_per_pixel` 2, 4 or 8, `pitch_bytes`, `per_pixel_alpha`), as
amdgpu_dm maps the DRM fourccs to DC surface formats. Rows are padded to 256 bytes;
backing is page-rounded and wholly cleared, including padding. Clearing yields
between 64 KiB chunks and invokes current authority for each chunk. Native CPU
HDP flush verifies NBIO's remap, fences stores, writes the flush aperture and
drains PCIe writes through the native NBIO read before address publication.

Preparation requires a reusable owner, every consumer stopped and MPC route
detached, and a powered, blank, drained selected HUBP with native 2D tiling
dimension. Active flips/locks, cursor/metadata/LUT fetches or uncertain power
reject before allocation or writes. Preconditions are rechecked after clearing.
The allocation is retained and marked published before register programming;
the fetch clock is temporarily enabled while blank. Native DCN4 programming
sets hubp2_program_pixel_format's uncompressed SURFACE_PIXEL_FORMAT (3 RGB565,
8 8888, 10 2101010, 24 16161616F) and CB_B/CR_R crossbar (swapped for the BGR
orders), hubp401_program_size's pitch in pixels minus one, primary and
secondary viewports, empty chroma viewports, VMID0 and normal non-stereo flip
controls. It does not touch the obsolete address-config fields. The high GPU
address precedes the low address which publishes the flip. Final drain, clock
disable and complete geometry/address/consumer readback are required. Only this
owned selected flip may remain pending; completion is not fabricated while
timing is stopped. Drain waits use the normal bounded asynchronous primitive.

`SurfaceApplied::{request,address,pitch_bytes,bytes}` in `Status::surfaces`
describes staged programming, not an active/latched framebuffer. Success enters
reusable `SurfacePrepared`; error enters `Failed` and cancellation retains
`PreparingSurface(pipe)`, blocking replay and clock changes. A HUBP power
transition invalidates its staged report without releasing its allocation.
Published backing remains excluded even if the owner is dropped, unless the
explicit `release_surfaces` protocol below succeeds. Unpublished backing is
releasable because no address reached hardware.

`unsafe Otg::release_surfaces(pipe)` (ColdBoot
`release_display_surfaces`) returns the page-rounded bytes reclaimed from that
pipe's current and parked front/back/cursor reservations. Callers first
unpublish the CPU scanout and drain its view epochs, exclude raw CPU references,
firmware/FAMS, GPUVM/writeback and other-engine use of these display-only
allocations, and retain exclusive display/PM/reset ownership. Inherited ranges
and another display's reservations are never released.

Release requires `PlanesRetired` with a report covering the pipe, then fresh
native evidence: disabled timing and non-sibling consumers, detached MPC routes,
idle MPCCs, no pending flips/updates, blank/drained/clock-disabled powered HUBPs,
inactive cursor/metadata/LUT/MALL requests, no held cursor lock, and consistent
power-gate request/PGFSM states. A gated HUBP's registers are not accessed.
Live siblings must still fetch their own recorded surfaces. Unlike restaging
retained memory, even the target's pending staged flip prevents reclamation.
The HDP remap is validated, CPU HDP writes are flushed and PCIe writes drained,
then the complete hardware/remap check runs again before any reservation can
be marked reusable. A failure before flushing retains everything without
writing; a failed flush or post-flush check also records `Failed`.

Success clears the released pipe's surface, memory, DPP, MPC, timing/blank,
requestor/deadline, scanout and cursor reports before returning reservations to
their pools. Other displays' records and historical diagnostics remain intact.
No await or fallible hardware access follows acceptance of the proof; a
cancelled CPU drain or incomplete hardware retirement cannot release memory.
Double release returns zero after the same checks. The monitor performs this
operation under the display owner lock after successful disable, unplug and
configuration teardown; the low-level stop functions retain their allocations
until an explicit release. Replug then allocates fresh buffers from the pool.
Link-loss retraining keeps its existing buffers. Native mapping caches remain
mapped, but retired CPU views cannot use them. Model tests cover reuse across
geometries, front/back/cursor and parked reservations, sibling preservation,
powered-off registers, cancellation, revocation and late hardware changes;
physical modeset/reclamation testing remains open.

`unsafe Otg::upload_surface(pipe,x,y,pixels)` and the matching
ColdBoot/platform `upload_display_surface` wrapper upload a bounded visible
row segment of a staged, stopped surface, rechecking geometry, address, power,
blanking and consumers and issuing the HDP flush. No CPU pointer escapes.
Bounds errors or stale configuration reject before memory writes; errors after
writes invalidate the report and quarantine the owner. All operations exclude
firmware/FAMS and concurrent display/HDP/clock/power writers and retain inherited
resources. DML2 request/deadline/watermark calculation, MPC setup, live flips
and visible scanout activation remain separate work.

`unsafe Otg::prepare_memory(&mut Gmc, pipe).await` configures DCN's physical
framebuffer aperture and VMID0 for an already staged owned surface. Matching
ColdBoot/platform `prepare_display_memory(pipe)` wrappers borrow the retained
GMC and display owners after the kernel engine proofs. GMC's register mapping
must match; its saved framebuffer geometry, flat VRAM page-table root and test
aperture must still match both GC12 and MMHUB4.1. The fault monitor's independently
owned interrupt-enable bits are allowed; translation, default and retry fields
remain fixed. The complete surface reservation, including padding, must lie in
the GPU framebuffer aperture. Its address is translated by FB base/offset;
the two-page GART test mapping does not back the surface.

The entire display tree must be stopped/detached, with the selected HUBP powered,
blank and drained and its owned surface programming intact. Global native DCN
FB base/top/offset use 16 MiB units; AGP is disabled with bottom above top.
VMID0 uses the retained physical VRAM PDE and logical start/end page numbers,
flat depth and 4 KiB block size. Root high is written before root low, which
publishes the context last. The native low-bit readiness wait is asynchronous
and bounded to 50 ms; address bits must also agree. No new PTEs, host mappings
or user contexts are created. Then the selected HUBP's fetch clock is briefly
enabled while blank to configure its 256 KiB system aperture and native L1
control (enabled, system access mode 3, unmapped access and ADM disabled).
Final checks require clock-off, stopped consumers, the same owned surface,
complete DCN register readback and a fresh matching GMC configuration.

Success enters reusable `MemoryPrepared` and records `MemoryApplied` in
`Status::memory[pipe]`: pipe, framebuffer base/inclusive top/physical offset and
the physical page-directory entry. This is historical setup evidence, never
fetch, flip or presentation completion. Reprogramming the global aperture clears
all prior memory reports; a HUBP power transition clears its report. Error
enters `Failed`; cancellation retains `PreparingMemory(pipe)`. Both quarantine
the display owner without speculative rollback or releasing either allocation.
Callers retain GMC, the display owner and every inherited resource and exclude
firmware/FAMS and concurrent hub/VM/display/clock/reset/power writers.

`unsafe Otg::prepare_dpp(&mut ClockManager, &mut Dccg, &mut Gmc, pipe).await`
stages native DCN401 processing for the retained full-frame XRGB/XBGR8888
surface. ColdBoot/platform `prepare_display_dpp(pipe)` wrappers borrow the
matching retained owners after the kernel engine proofs. It requires the same
surface and DCN VM setup, current readback-checked clocks, matching stopped
timing and prepared RGB black OPP, and a disconnected, blank, drained HUBP.
A full-frame surface matches the timing's active size; a placed one is
scaled through SPL (see "Navi 48 plane scaling and overlay planes"), on the
display's own pipe or an overlay's. The selected DPP clock must be disabled,
resets clear, its cursor disabled with no pending update, and inherited CNVC,
scaler and CM updates complete. Test clocks and forced/manual line-buffer
power policy are rejected before writes. Other DPP instances stay untouched.

Preparation temporarily enables the native DPP clock (bit 4, no obsolete rate
divider), wakes scaler LUT and iSHARP memories with bounded asynchronous waits,
and rechecks stopped consumers after each wait. Conversion follows
dpp401_dpp_setup for the surface format: CNVC_SURFACE_PIXEL_FORMAT as the
HUBP's except 25 for ABGR16161616F, ALPHA_EN except for RGB565, zero expansion
and an identity CNVC crossbar; red/blue selection remains in the HUBP. FCNV
bias/scale and HDR multiplication are identity, pre-degamma/post-CSC/
gamma/keying/de-alpha are bypassed, and the encoded RGB values pass through:
amdgpu_dm's default plane color state, which is all FP16 needs too (its values
pass unscaled and the output denormalization clamps them). The line buffer
carries alpha (LB_DATA_FORMAT ALPHA_EN) exactly for the formats MPC
preparation below blends per pixel; the partition count is the same either
way. The scaler is programmed from SPL's scaler data
(`amdgpu_dcn401_dscl::program`): a unity segment in native
`SCALING_444_BYPASS` (mode 0, still a floating-point line buffer; mode 6 full
bypass is not used), a scaled one with its ratios, inits, taps, polyphase or
EASF coefficients (loaded into the coefficient RAM not in use, then
selected) and recout/MPC size. The line-buffer configuration is
dpp401_dscl_find_lb_memory_config's on SPL's data. iSHARP stays disabled.

Final checks require DPP clock-off, unchanged live owners/surface/timing/VM,
stopped consumers and full DPP register readback. `DppApplied` records the
surface, timing, line-buffer configuration and CNVC/scaler/CM pending bits in
`Status::dpps[pipe]`; success enters reusable `DppPrepared`. Double-buffered
changes can remain pending while timing is stopped, and no latch/presentation
completion is inferred. The owner heap-allocates its accumulated status to keep
per-pipe reports out of nested driver and async owner-move stack frames; the
public status accessor still returns a historical snapshot by value.
Repeated preparation rejects while its report exists;
timing preparation/retirement, HUBP power transitions and global VM preparation
invalidate dependent reports. Errors enter `Failed`; cancellation retains
`PreparingDpp(pipe)`, blocking replay/clock changes without speculative rollback.
All owners and allocations remain retained. Callers exclude firmware/FAMS and
concurrent display/hub/VM/clock/reset/power writers. MPC and requestor preparation are described below;
bandwidth/deadline admission, route activation and physical-card validation
remain required.

`unsafe Otg::prepare_mpc(&mut clocks, &mut dccg, &mut gmc, pipe)` stages
full-frame RGB composition for an owned DPP/surface: per dcn401_update_mpcc_sequence,
per-pixel premultiplied alpha for the formats amdgpu_dm's
fill_blending_from_plane_state blends so under the primary plane's default
pre-multiplied blend mode (ARGB/ABGR8888, ARGB/ABGR2101010, ARGB16161616F;
not ABGR16161616F, as in Linux), global opaque alpha for the rest. ColdBoot exposes
synchronous `prepare_display_mpc(pipe)`; the platform wrapper is asynchronous
only to acquire its owner mutex. Preparation checks the retained surface, VM,
DPP, current clock and timing owners, matching OPP format, blank/drained HUBP,
disabled DPP/fetch clocks, and every disconnected MPC route before writing.
It programs native top-layer-only mode, global opaque alpha, unity top/bottom
gains and black background, with stereo disabled. XRGB/XBGR's unused alpha byte
does not affect coverage. OGAM, its gamut remap, MCM shaper/3D LUT/post-1D LUT,
both MCM gamut remaps and output CSC are explicitly bypassed. Movable color
management is placed before blending. Denormalization follows the owned OPP's
8/10/12-bit depth, with unclipped full-range 12-bit clamp limits. Bypass does
not write LUT RAM, coefficients, power policy or shared coefficient formats.
All top/bottom/OPP/update-lock/output selectors remain detached.

Each masked write is checked, followed by complete source/owner and MPC
readback. `MpcApplied` records the DPP, output depth and nine historical
non-bypass CURRENT-selector bits in `Status::mpcs[pipe]`. A bypass request
readback is not a hardware latch: nonzero CURRENT fields are recorded while
timing is stopped. Success enters reusable `MpcPrepared`; repeated preparation
rejects until dependent state is invalidated. Timing preparation/retirement,
OPP preparation, HUBP power transitions and global VM preparation invalidate
dependent reports. Any programming/readback failure enters sticky `Failed`,
with no speculative rollback or allocation release.

`unsafe Otg::prepare_requestor(&mut clocks, &mut dccg, &mut gmc, pipe).await`
stages bounded physical-RGB requests and the native default single-pipe buffer
allocation after MPC preparation. ColdBoot/platform expose asynchronous
`prepare_display_requestor(pipe)`. This binds to the same owned surface,
memory, DPP, MPC, timing and clocks. It partitions DCN401's 21 64-KiB CRB
segments into five for the selected pipe's DET (320 KiB), zero for other DETs,
and sixteen for compbuf (1 MiB). The owned pitch must fit at least two rows in
DET. This is a storage policy, not proof that a mode meets its fetch deadlines.

Preflight rejects inherited in-progress allocations, overcommit, compbuf
configuration errors, enabled allocation IRQs and pending acknowledgement
writes. The read-only compbuf DONE status is preserved even when set with its
IRQ disabled. Every shrinking allocation must acknowledge CURRENT before any
allocation grows; requested and current totals never exceed the native CRB
capacity. The driver uses bounded asynchronous waits and rechecks the full
allocation, retained sources and current owners after each acknowledgement.
Timeout, cancellation, revocation, removal, late changes and dropped writes
leave resources retained in `Failed` or `PreparingRequestor(pipe)`; neither
state permits replay or ordinary clock changes.

The requestor uses native DCN4 six-field RGB/five-field chroma layouts, 8-KiB
chunks with a 1-KiB minimum, one-line linear swaths and zero VM/PTE groups for
the physical framebuffer aperture. DET plane-one base is zero. Expansion modes
are DRQ=2 and PRQ/MRQ/CRQ=1. The selected HUBP uses its matching VTG, bounded
requests and no MALL surface/cursor/prefetch; the native early cursor-request
mode is set while the cursor remains disabled. Compbuf reserved space is 256
units of 64 bytes, from native `pixel_chunk_size / 32`. The HUBP clock is enabled
only around request programming, with blank/drain rechecked, and disabled again
before final source and register verification. Existing HUBP allocation,
timeout and underflow errors and timeout-IRQ ownership reject preparation.

Success enters reusable `RequestorPrepared` and records the surface and byte
sizes in `Status::requestor`; timing/OPP/MPC changes, HUBP power transitions and
global VM setup invalidate this shared report. Callers retain all owners and
inherited resources on every outcome and exclude firmware/FAMS and concurrent
display/hub/VM/IRQ/clock/reset/power writers. DLG/TTU and
watermark admission, route activation and live presentation are separate
steps described below. Physical RX 9000 validation remains open. Neither
preparation API starts fetch or publishes an active framebuffer.

`amdgpu_dcn401_dml::admit(&Soc, &Mode) -> Result<Plan, Error>` is the native
scanout admission calculation: Linux DML21's DCN4 mode-support and
mode-programming path, evaluated in fixed point with no hardware access. It
admits the shape the native path implements: progressive streams of linear
RGB planes (`Mode::planes`: the primary, scaled or not, and overlays; see
"Navi 48 plane scaling and overlay planes"). CalculateDETBufferSize shares
1280 KiB among the pipes without an override: DC's minimize_det_reallocation
uses pixel-rate budgets per stream, then bandwidth per plane and full-swath
minimums, in 64-KiB segments. A single tiled RGB pipe uses unbounded requesting,
a two-swath DET of at least 128 KiB and the remainder as compbuf; bounded
configurations leave at least one compbuf segment. `Plan::plane(k).det_bytes`
is each pipe's allocation for that plane. The retained regression fixtures use the same
DC settings, including the ForceSingleDPP allocation before MPC admission. `Mode::bytes_per_pixel` is DML's source format
(2 `dml2_444_16`, 4 `dml2_444_32`, 8 `dml2_444_64`; anything else is
`Invalid`) and the pitch must be whole 256-byte requests at that depth; the
request width, swath, DET lines, read bandwidth and deep-sleep DCFCLK follow
it (`tests/dcn401_dml21/format_vectors.txt`, checked against Linux with
`PIXEL_BYTES`). A configuration whose SDP bandwidth would make DPMM raise
DCFCLK/FCLK above the pinned UCLK's state is `ClockState`: the port plans
only at that state. VUpdate/VReady widths at the programmed clocks are
rounded up from their exact value. GPUVM/HostVM,
DCC, MALL/SubVP, cursor, tdlut, dynamic metadata, writeback and immediate
flip are excluded rather than approximated.

ODM follows DML's `dml2_odm_mode_auto` (DecideODMMode,
CalculateODMConstraints, ValidateODMMode): a stream initially takes the fewest of one
to four pipes (DPP/OPP each and, with DSC, a DSC each) whose DISPCLK
(CalculateRequiredDispclk: the pixel clock over the pipes, never below half
of it for HDMI TMDS 4:2:0) fits the downspread-limited maximum, at least
one per started 5760 DSC pixels or 4096 4:2:0 pixels, two for more than four
slices, three for more than eight and four for a three-pipe split whose
slices are not twelve. 3:1 and 4:1 lines divide by four (OTG_H_TIMING_DIV_BY4),
3:1 may split unevenly without DSC, and with DSC the slices split evenly
(all twelve on three). More than the pool's pipes (four unfused) in all is
`Pipes`. `Plan::pipes`
(1 to 4) reports the decision; every pipe shares every programmed value
except the DLG blank end, which each further pipe moves by the segments
before it (`Plan::odm_refcyc_h_blank_end: [u32; 3]`, `Plan::pipe_dlg`).
The Vmin phase then tries to lower a single DP stream's DISPCLK toward
600 MHz using more ODM pipes, retaining supported partial progress. HDMI
TMDS/FRL (`Mode::hdmi`), incompatible timing divisibility, base MPC combine
and DSC slice constraints exclude candidates as in PMO. The same phase runs
after P-state strategy search. A live P-state change that would move pipes
stays pinned until a full modeset can adopt that topology.
`tests/dcn401_dml21/odm34_vectors.txt` (1927 configurations: 8K, 10K, 5K and
4K480 streams at every depth, with DSC of 4 to 24 slices, HDMI 4:2:0, beside
other streams, and every configuration the older files marked "Unsupported
odm") is answered by Linux DML21 and replayed by
`dcn401_dml_matches_linux_dml21_odm34_vectors`. `dml::admit_native` (what
the modeset, platform and MST admission call) also refuses (`Unsupported`)
an ODM split whose other horizontal boundaries, segment widths
(OPTC_SEGMENT_WIDTH) or segment memories the native OTG cannot take
(`dml::odm_timing_ok`); Linux leaves them a TODO. Native modeset, boot,
platform and plane admission also validate DSC401's limits against the
**final** `Plan::pipes`: at most four slices and 5184 pixels per DSC, slices
split evenly, and twelve slices for ODM 3:1. DML's generic 5760-pixel limit
alone is insufficient. `dml::dsc_shape(timing, slices, dispclk_max_khz)` is
a conservative base-ODM diagnostic; candidate selection cannot use it to
reject a stream before Vmin optimization or joint memory admission.

MPC combine follows DML's auto `mpcc_combine_factor`, which DC leaves for
DCN401 (`dml::Policy::NATIVE`; the older vector files replay with factor 1):
a plane in ODM bypass whose single DPP needs more than the downspread-limited
DPPCLK maximum (MinDPPCLKUsingSingleDPP) or cannot take the viewport's swath
(SingleDPPViewportSizeSupport: DET, the 15360-pixel linear swath, the line
buffer at its taps) takes two DPPs (`PlanePlan::dpps`), each with half the
viewport, half the DPPCLK, and the swath, delivery, prefetch and deep-sleep
terms of DPPPerSurface 2; both program identical registers. DCN4's
`mpc_combine_limit` is two. The decision is the same for every surface:
linear or GFX12-tiled (the 6144-pixel tiled swath limit, 7680 for 4:2:0,
4320 for 4:2:0 and 3072 for 64-bpp DCC scanned vertically), RGB or 4:2:0
(each DPP half the luma and chroma swath, the DET split per pipe), with or
without DCC (each pipe's DCC overhead), scanned horizontally or rotated
90/270. `admit_all_with` then runs dml2_top_soc15's mcache phase whatever the
policy, with PMO's dynamic ODM on as DC runs it
(dml21_populate_pmo_options: `disable_dyn_odm = !minimize_dispclk_using_odm`,
false on DCN401): a DCC plane of a supported configuration whose pipes cannot
place its mcaches (dml2_top_mcache_validate_admissability: at most one
boundary within a pipe's share of the surface width, no more boundaries than
pipes; every surface holds up to DML2_MAX_MCACHES (8) mcaches,
`dml::MAX_MCACHES`, and a count past it, which Linux writes beyond its
arrays and which num_dcc_mcaches refuses anyway, is `Unsupported`) makes
pmo_dcn4_fams2_optimize_dcc_mcache act and mode support run again. Several
streams, or one stream in ODM bypass (optimize_dcc_mcache_no_odm): the plane
takes one more DPP from the free pipes, up to the limit; a failing plane on an
ODM stream, at the limit or without a free pipe is `Unsupported`. One stream
on an ODM split: with a free pipe per plane of the stream,
increase_odm_combine_factor raises the stream's ODM factor (from the plane's
DPP count when auto, then one further: 2:1 to 3:1 to 4:1) and mode support
runs on the forced factor (ValidateODMMode still applies); Linux indexes the
stream descriptor by the failing plane's index, so only a failing first
plane changes anything, and any other is `Unsupported`. The retained fixtures use PMO's
`disable_dyn_odm = false` with per-stream dynamic ODM allowed;
surface_vectors.txt's single-stream ODM section (8K and 4K120 DCC planes of
two to four mcaches) has Linux raise the ODM factor and fill allocations past
three slices.

A multi-pipe plan is programmed as ODM 2:1, 3:1 or 4:1 (optc401_set_odm_combine). The
modeset gives it the further OPP heads DC acquires (dcn32_acquire_free_pipe_
as_secondary_opp_head: the current OTG master's own further OPP heads, else
pipes the current state leaves free, lowest first; see "Pipe acquisition"),
left to right in that order, a DPP-only clock on
each (`dccg::PixelClock::OdmSegment`, plus its DSCCLK), and lights it with
`otg::Request::odm` and `otg::SurfaceRequest::odm` naming them
(`otg::SplitPipes`: one to three further pipes). The OTG takes every OPP as
a segment (OPTC_NUM_OF_INPUT_SEGMENT the count less one, unused segments
0xf), the segment width of resource_get_odm_slice_dst_width (the line over
the count, whole pixel pairs for 4:2:0) and for 3:1 OPTC_SEGMENT_WIDTH_LAST
(the rest of the line), each segment's own first- then second-preferred line
memories (decide_odm_mem_bit_map; a line needing another display's is
refused: at most 4096 pixels per segment), and H divide-by-two for 2:1 or
divide-by-four for 3:1 and 4:1 (every horizontal boundary divisible by it);
each OPP formats and blanks its segment at its offset (a 4:2:0 segment after
the first takes one extra left-edge pixel); each segment's DSC compresses its
segment with its share of the slices while the stream's PPS stays
whole-picture. Each ODM pipe's HUBP fetches its segment of the same surface
(viewport X offset), its DPP/MPCC/DET/requestor (VTG the master OTG) and
DLG/TTU follow, and start, flip, stop, underflow recovery and live checks
act on every segment under the master OTG's one lock. The cursor is placed
per segment and enabled only on the segments it overlaps
(`CursorApplied::shown`). The display holds its ODM pipes from staging
until retirement (`Siblings::pipes`); its teardown retires the timing (every
segment's DSC off, every segment disconnected) before stopping each DSC
clock. `ScanoutRunning::odm` names the pipes.

An MPC-combined plane (`PlanePlan::dpps` 2 in ODM bypass) takes a further
pipe as DC acquires it (resource_update_pipes_for_plane_with_slice_count
after every plane is added: a free pipe of the current blending tree, else
one the current state leaves free, lowest first, the slice right after its
plane in the tree; see "Pipe acquisition") with a DPP-only clock at its
DPPCLK; `SurfaceRequest::mpc` names it. Each slice's
HUBP/DPP takes SPL's viewport and recout for its MPC slice
(`spl::Input::mpc_slice`, calculate_mpc_slice_in_timing_active: equal shares
of the plane clip, the remainder to the last slices); both slices' MPCCs
blend in their stream's one tree, the second directly below the first
(acquire_dpp_pipe_and_add_mpc_slice's bottom pipe), and every slice fetches
the plane's address under the one OTG lock (`ScanoutRunning::mpc`,
`OverlayScanout::mpc`). MPC combine never joins ODM, as DML21 decides it.

`Soc` carries the board state DML depends on: the pinned UCLK, FCLK/DCFCLK DPM
ranges, minimum SOCCLK, DISPCLK/DPPCLK maxima, the UMC channel count, DENTIST
VCO and DCHUB reference clock. Constants come from `dml2_socbb_dcn401`, the
DCN4 variant-A QoS table and `dml2_dcn401_max_ip_caps`. The calculation applies
DCN4's min-clock-table derivation for the single UCLK level, checks bandwidth
against the maximum clocks and latency/programming at the derived state, and
reproduces DPMM's DISPCLK/DPPREFCLK/DPPCLK rounding. These pinned plans
never search PMO's UCLK P-state strategies (`dml::pstate::admit` does, see
"Navi 48 UCLK P-state switching"); the UCLK watermark is still the real
blackout-plus-urgent value. PMO's stutter
phase is kept: 54 us of blank is reserved for self-refresh when the nominal
blank is at least three times that and the mode still passes.

A `Plan` records its inputs, minimum clocks (DML's DCFCLK/FCLK/UCLK state is
below the pinned floors), `GlobalSync`, the nonzero HUBP DLG/TTU fields, the
DCHUBBUB watermark set Linux programs into sets A and B, arbiter values, DET
size and stutter reservation. `Error` names the first failing check: invalid
inputs, unmodeled shape, unavailable clock state, pixel clock, buffers,
outstanding-request/ROB latency, prefetch, urgent latency hiding, bandwidth,
GDDR6 temperature-read blackout, a programmed value outside its dcn_4_1_0
field (DLG/TTU, watermark, fraction, request-limit and stall fields), or
more pipes than DCN4.0.1 has. The
result is deterministic and is only a calculation until bound and programmed.

`ColdBoot::display_admission(&Mode)` (and the platform's asynchronous
`display_admission`) builds the `Soc` from live owners and admits the mode
without writing anything. The started DAL clock owner now also records
DALSMC `GetNumUmcChannels`, refusing zero or more than 64 channels (Linux
falls back to VBIOS), and `GetDcModeMaxDpmFreq` for DCFCLK, SOCCLK, DTBCLK,
DISPCLK and UCLK. As with Linux's `use_clock_dc_limits`, a DC-mode maximum
below the table maximum caps `Range::max_khz`, and with it the pinned
DCFCLK/UCLK floors and DISPCLK/DPPCLK/DTBCLK request limits. UCLK is that
pinned floor. `Dccg::dentist_vco_khz` reads the DENTIST PLL (9.16 FbMult times
the 100-MHz DFS reference) and refuses a zero VCO rather than assuming
4.5 GHz. `Otg::admission_soc` derives the DCHUB reference from
`DCHUBBUB_GLOBAL_TIMER_CNTL` and the VBIOS DCE crystal, which ColdBoot keeps:
REFDIV 2 halves it. A stopped timer or a reference outside 40-60 MHz is
unsupported; the timer is never reprogrammed.

`unsafe Otg::prepare_deadlines(&mut clocks, &mut dccg, &mut gmc, pipe, &Plan,
crystal_khz).await` (ColdBoot/platform `prepare_display_deadlines`) programs
an admitted plan after requestor preparation. It first re-admits the plan from
its own inputs and refuses any difference, so an edited or hand-built `Plan`
is not admission. It then binds the plan to the current owners: the retained
MPC/DPP/surface/memory/timing sources and requestor allocation verify as for
the requestor; the timing, global sync and legacy DP SST signal must equal the
plan; each surface must match its planned plane, pitch and per-pipe DET; applied DISPCLK, DPPREFCLK and pipe DPPCLK must be at least the plan's;
the pinned UCLK and DCFCLK floors must equal the ones it assumed; and the live
DCHUB reference must match. Any mismatch is `Invalid` with no writes.

Programming follows `hubp401_setup`/`setup_interdependent` with fetch
stopped and the HUBP clock enabled only around the writes. It enters DLG
mission mode (only that bit must read back, as Linux never reads it), writes
every nonzero DLG/TTU field and explicitly zeroes the VM/PTE/meta/flip/
chroma/cursor/3D-LUT fields. `HUBP_VREADY_AT_OR_AFTER_VSYNC` uses Linux's
hwseq rule, where VREADY before blank start is "before". Watermark sets A and
B get identical values in the `hubbub401_program_*_watermarks` layout: one
SR enter/exit pair for all four levels, and the temperature-read watermark in
both UCLK and FCLK "1" slots. The SDPIF request limit, P-state stall threshold
and a clear `HW_DEBUG[5]` follow Linux, and USR retraining is not forced.
Self-refresh is force-disallowed in `DCHUBBUB_ARB_DRAM_STATE_CNTL` until
stutter is validated, although the plan still budgets its blank. The DCHUB
pstate force stays released: PMFW keeps UCLK switching disabled, and GDDR6
temperature reads use the same allow path. Every pipe of every plane then
gets hubp401_program_mcache_id_and_split_coordinate (dcn401_program_pipe's
step 13): `DCHUBP_MCACHEID_CONFIG` (REG_READ and equal MALL_PREF ids, luma
and chroma) and `DCSURF_VIEWPORT_MCACHE_SPLIT_COORDINATE`, from the plan's
`McacheAllocation::pipe_regs` over that pipe's own SPL luma (and 4:2:0
chroma) viewport x and width, as dml2_top_soc15_build_mcache_programming
assigns them, so each ODM segment or MPC slice of a DCC plane reads the
mcaches its viewport crosses; without DCC, or where a viewport spans more
than two mcaches, reset_mcache_allocations' unassigned ids (0xf) and split
(0xffff). Those registers are written whole and compared raw, since their
all-ones value is legal. Every field is read back after the owners are
re-verified; `DeadlinesApplied` records the plan and enters
reusable `DeadlinesPrepared`. Requestor/timing/OPP/MPC/HUBP-power/VM changes
invalidate it with the requestor report, and failure or cancellation is
sticky as for the other preparation steps. Route connection, fetch enable and activation
remain separate and must rebind the plan.

`unsafe Otg::start_scanout(&mut clocks, &mut dccg, &mut gmc, pipe,
crystal_khz).await` (ColdBoot/platform `start_display_scanout`) makes the staged
surface the visible source of a pipe whose legacy DP SST stream is in
`DpVideoRunning` with the OPP DPG producing black. It rebinds the programmed
deadlines with DCCG's read-only `retained_timing_clock` (the link is live),
re-reads the surface, memory, MPC, requestor and DLG/TTU/watermark registers,
and requires: the matching OTG running with no held lock, GSL or MPCC update
lock; no OTG, pipe-update, OPTC or DPG transaction pending; no HUBP or OPTC
underflow; and a blank, drained, clock-gated HUBP with DPP clock gated,
detached routes and the DPG still black.

Following Linux's plane-enable path, it then ungates the HUBP and DPP clocks,
takes the OTG master-update lock (selected via `OTG_MASTER_UPDATE_LOCK_SEL`;
the lock status must assert, where Linux proceeds after 10 us), and forces
P-state change off for the transition. Under the lock it returns the DPG to
video mode, inserts MPCC n (bottom none, top DPP n, OPP n, update-lock OPP n,
output mux), re-arms the surface address (high, then the publishing low) and
clears `HUBP_BLANK_EN`/`HUBP_TTU_DISABLE`. Releasing the lock latches all of
it at one VUPDATE. Within a bound of three frames plus 5 ms it waits for
`dcn401_post_unlock_program_front_end`'s evidence: no flip pending and
`SURFACE_EARLIEST_INUSE` equal to the owned address (a requested-address
readback is not presentation), with DPG disabled and its pending bit, the OTG
update and pipe-update pending bits clear, and the MPCC no longer disabled.
The P-state force is then released, the routes and unblank are read back, and
two fresh frame counts must pass without underflow. `ScanoutRunning` records
the plan, address and frames in `ScanoutRunning(pipe)`.

`unsafe Otg::stop_scanout(...)` reverses it: under the lock the DPG returns to
the staged black value and every MPCC route detaches; after unlock it waits
for the black latch and an idle or disabled MPCC, then for
`HUBP_NO_OUTSTANDING_REQ` before blanking the HUBP, and gates the HUBP and DPP
clocks only after that. Linux's DET release and power gating are not
performed: the staged state is re-verified and the owner returns to
`DpVideoRunning`, so the pipe can start again. Any timeout, underflow,
readback mismatch, owner change or cancellation after the first write leaves
`Failed` or the transitional state; nothing is replayed or released, and the
surface must stay allocated because fetch retirement was not proven.
`unsafe Otg::check_scanout(...)` is the read-only health check of a live pipe.
It rebinds the deadlines as above and re-verifies the running DP stream with
`fetchers_stopped_except`: the owned pipe must show exactly its live fetch
(HUBP unblanked with TTU enabled and clock on, DPP clock on, DPG fields zero,
MPCC not disabled, all routes connected, cursor off, requested and
EARLIEST_INUSE addresses equal to the owned surface), while every other powered
HUBP must still be stopped and every auxiliary fetcher disabled. The black-video
OPP verification accepts the DPG in video mode only for that pipe. Mismatches
are reported without writes. A HUBP or OPTC underflow (on check, or during
start) records `ScanoutUnderflow` (pipe, address, HUBP status, OPTC bit, frame)
in `Status::underflow`, runs the stop sequence without failing on the sticky
status, strobes `HUBP_UNDERFLOW_CLEAR`/`OPTC_UNDERFLOW_CLEAR`, requires the
status to stay clear with fetch blanked, rebinds the owners and returns to
`DpVideoRunning`. If that cannot be proven, the pipe is `Failed`. Other start
failures quarantine without recovery. Rebinding a live pipe tolerates the
HUBP underflow status bits in the requestor check (they are the scanout's to
detect and recover); every other requestor error, and an underflow inherited
by setup, still fails it. Without that, an underflowed live pipe could be
neither checked nor stopped.

Model coverage runs owner-level start/check/stop over a chain staged by the
real steps from a DML plan (surface, VMID context, timing, black DPG, DPP, MPC,
requestor, deadlines, TMDS link and black video) on every pipe with
independent PHY/stream/pipe routing: delayed VUPDATE latches, lost writes
(caught by readback), an ungranted lock, a never-latching address, owner
changes during start and stop, cancellation at the lock wait, transmitter
clock loss and frozen timing under scanout, and underflow during start and
while running.

`unsafe ColdBoot::modeset_display(pipe, fill).await` (platform
`modeset_display`) orchestrates the above on one legacy DP SST or TMDS HDMI
connector. It scans the routed sinks, selects the first DisplayPort port whose
sink answered with DPCD and an EDID preferred mode that `timing_from_edid`
accepts (from the 128-byte base block; extension blocks follow it), and links
it at the sink's maximum lanes and rate. A sink that cannot carry the mode's
8-bpc payload is skipped (`ModesetError::Link` if nothing else fits). With no
such DP sink, the first HDMI port whose EDID carries the HDMI Licensing VSDB
(`hdmi_caps`; a DVI sink never receives HDMI packets) and whose preferred mode
`hdmi_fits` is selected (`Selection::hdmi`, zero lanes). `hdmi_caps` reads, as
DRM does, the VSDB Max_TMDS_Clock and the HF-VSDB or HF-SCDB (extended tag
0x79) Max_TMDS_Character_Rate and SCDC_Present, honouring DRM's minimum block
lengths, and the VSDB DC_30bit/DC_36bit deep-colour flags. `hdmi_depth` picks
the deepest declared depth up to `max_bpc()` whose character clock fits,
stepping down 2 bpc like amdgpu_dm's stream validation; `max_bpc` defaults to
8 and the `amdgpu.max_bpc=10|12` boot option raises it. Within it each
connector's "max bpc" (`requested_bpc`, see "Navi 48 connector max bpc")
caps that connector's stream, on HDMI and DP alike. The blank is staged at
that depth. A character clock fits at or below 340 MHz within any declared VSDB maximum, and
above it (to `TMDS_MAX_KHZ`, 600 MHz) only with SCDC and an HF rate covering
it. Before the link starts an SCDC sink is configured as Linux's
`write_scdc_data` does: sink version read, source version 1 written when the
sink reports 1, then TMDS_Config 3 (scrambling, 1/40 clock) above 340 MHz or 0.
A scrambled mode's SCDC failure fails the modeset (`ModesetError::Scdc`); the
legacy write's result is ignored, as in Linux. A normal stop writes
TMDS_Config 0 after the video stops and before the link stops; an unplug does
not address the departed sink. Its pipe
clock is the TMDS divide-by-four rate and its timing `Signal::Tmds`, and the
link starts with `prepare_hdmi_link` (stream = pipe), `start_hdmi_video` and
scanout. HDMI has no link status: `check_modeset` reports HPD and scanout
only, `retrain_modeset` is `Unsupported`, and stop/unplug use
`stop_hdmi_video` then `stop_hdmi_link`. The monitor enables HPD on every DP
and HDMI port.
Training then walks narf's fallback ladder (`link_candidates`), trying only
settings that carry the mode: the link rate drops first; below RBR the lanes
halve and the rate restarts at this attempt's starting rate. Legacy DSC also
walks this ladder while keeping the admitted bpp, PPS, timing and DML plan:
only settings that carry that compressed payload plus slice overhead after
FEC are tried. Changing bpp/slice geometry requires a new admission and is
not done inside link fallback. When every carrying 8b/10b setting of an SST
sink without 128b/132b caps is refused, `start_link` follows Linux's
`dp_verify_link_cap`: it trains the rest of the ladder from the sink's caps
(`verify_ladder`) without a stream, stops the link again and records the first
setting that trained, else one RBR lane, as the port's `VerifiedLink`
(`verified_link`), keyed by the sink's scanned DPCD and base EDID. It returns
`ModesetError::LinkReduced` only when that link is below the caps.
`ColdBoot::scan_display` applies the record as `display::Sink::verified_link`
(`apply_verified_links`), so `dp_caps`, selection, offered modes and DSC
(`dp_dsc`/`refine_dsc`) use the verified link and no 128b/132b; another sink,
a changed EDID/DPCD, a nonresponding or empty port drops it.

DSC follows amdgpu_dm's SST policy for a dongle-less DP sink on either
encoding, at every depth amdgpu_dm_create_validate_stream_for_sink tries:
`dp_sst_stream(timing, caps, depths, max_dispclk_khz) -> Option<DpSstStream {
lanes, rate, dsc, depth }>` walks `dp_depths` (the EDID 1.4 depth, 8 when
undefined, up to `max_bpc`, deepest first) and at each depth takes the
stream raw when a link carries it (`dp_link_bpc`), else compressed from that
depth, else the next depth; a deeper compressed stream is preferred to a
shallower raw one, as in Linux (6 bpc, which the native encoders cannot
send, is never tried). `dp_dsc(timing, caps, max_dispclk_khz, bpc)` runs only when no
uncompressed setting carries the mode at `bpc`, and compresses with
`dc_dsc_compute_config` against `dc_link_bandwidth_kbps` at the sink's
maximum link: 4 lanes x the best UHBR rate (`uhbr_kbps`, 128b/132b
encoding, FEC inherent, no FEC cap needed) when `DpCaps::uhbr` is nonzero,
else the maximum 8b/10b link with FEC (FEC cap required). The result is a
provisional link/decoder candidate; hardware shape is checked only after
full admission chooses the actual ODM split. A 5440-pixel stream with four
slices can therefore pass single-DP Vmin ODM 2:1 (2720 pixels per DSC) even
though base ODM bypass exceeds DSC401's 5184 pixels. HDMI, multistream and
memory-starved configurations must independently pass their actual plans.
`dsc_link(timing, cfg, caps)` is the link for the compressed bandwidth
(`dc_dsc_stream_bandwidth_in_kbps`, unpadded): the maximum 8b/10b link with
FEC when it carries it, else the first 128b/132b setting upward, lanes before
rate. A UHBR sink therefore never compresses onto 8b/10b (16 bpp is two
thirds of 24 bpp, and 8b/10b with FEC carries less than two thirds of UHBR10
at any lane count), and uncompressed UHBR always wins over DSC at the same
depth. Configuration admission regenerates candidates with the board's
DISPCLK and searches complete configurations from the selected depth down.
A final shape, pipe or memory-admission failure tries the next depth,
including raw output when it fits. Fixed running streams retain their exact
selection during beside admission. A leading-prefix fallback returns only
its normalized selections and matching plans; a rejected stale suffix is
never re-admitted by a later DML-only pass. A compressed UHBR stream carries no
audio. Fallback keeps the admitted PPS (`selected_dp_candidates`): Linux's
`dp_lt_fallbacks` through its 128b/132b settings that carry the compressed
stream for a UHBR link, narf's 8b/10b ladder for an 8b/10b one. DML21
admission takes the same inputs on both encoders. Retained DSC/ODM/UHBR
fixtures exercise that Rust policy, including the explicit DP2P0 cases. On the HPO path `otg::Request::dsc` is
accepted for `Signal::HpoDisplayPort` SST: the pipe's DSC and OPTC compress
from timing staging (link_set_dsc_on_stream programs nothing more for HPO),
`DP_SYM32_ENC_VID_PIXEL_FORMAT.PIXEL_ENCODING_TYPE` is set, and after the
encoder is enabled and mapped `start_uhbr_video` writes DP_DSC_ENABLE 1 (read
back), then sends the PPS as `dcn31_hpo_dp_stream_enc_set_dsc_pps_info_packet`
does (GSP11 payload size 3, VPG n+5 generic packets 11-14 with header
00 10 7F 00 latched immediately, GSP11 line 2, VBID[6] line 3, GSP11 and
SDP on), before the SST payload, whose slots, VC rate and minimum blank
width (`uhbr_dsc_payload`) use the compressed bandwidth. `stop_uhbr_video`
writes DP_DSC_ENABLE 0 (unchecked) and turns GSP11 off with payload size 0
after the encoder, before the timing; the DSC stays for a restart until the
timing retires. `DscConfig::bpc` is the input depth a configuration was
computed for (the timing's `display_color_depth`, 8, 10 or 12): the DSC's
`DSC_CIF_CONFIG0` input depth and the PPS's `bits_per_component` and rate
control follow it, the DIO and HPO encoders and MSA/VSC keep signalling the
stream depth, and the blank request's depth must equal it (the OPP feeds the
DSC that depth; `Error::Invalid` otherwise).

HDMI FRL DSC follows amdgpu_dm's FRL policy (`apply_dsc_policy_for_stream`,
`create_validate_stream_for_sink`): at each depth, deepest first, a stream
is compressed from that depth only when it does not fit the sink's maximum
FRL rate raw; a depth DSC cannot form (the HF-VSDB's DSC_10bpc/DSC_12bpc
decide 10- and 12-bpc input) tries the next.
`amdgpu_dsc::HdmiDscCaps::parse(flags, max_frl_rate, total_chunk)` reads the
HF-VSDB DSC bytes as drm_edid does and `DscSinkCaps::from_hdmi` is
`dc_dsc_parse_dsc_edid` (`is_frl`, `all_bpp`, `total_chunk_bytes`).
`compute_frl_config(sink, max_dispclk_khz, max_rate, timing, vic)` is
`dc_dsc_compute_config` on `LinkEncoding::HdmiFrl`: `hdmi_num_slices` and
`hdmi_bpp_x16` (`hdmi_dsc_get_num_slices`/`hdmi_dsc_get_bpp` with the
`prim_bpp` tables for CTA/HDMI VICs), `frl_params` per FRL rate
(`compute_bpp_x16_from_frl_params`), the FRL `decide_dsc_bandwidth_range`
branch with no DP slice overhead, and the FRL minimum-bpp fallback;
`DscConfig::frl = Some(FrlDscLink { all_bpp, max_rate })`. The FRL rate is
the lowest one whose compressed capacity check passes:
`amdgpu_frl_cap::frl_cap_check` with `FrlCapInput::dsc = Some(FrlDsc { slices,
slice_width, bpp_x16, vic, all_bpp })` is `dml1_frl_cap_chk_compressed`
(prim_format tables, 192 kHz audio reserve) returning `FrlCap::Ok {
audio_packets_line, borrow, hc_active, hc_blank }`, and `dsc_borrow` is
`frl_modify_borrow_mode_for_dsc_padding` (Linux's 100 Hz pixel clock units
kept). `modeset::hdmi_stream` selects the stream (RGB at 12, 10 then 8 bpc, raw or
compressed, then 4:2:0 raw, as Linux orders encodings and depths;
`frl_dsc(.., bpc)` compresses at a depth). `Selection::frl_caps` retains the
sink's HDMI decoder/depth/subsampling caps and verified raw FRL cap, alongside
the chosen link rate. Final configuration admission retries those candidates
from the selected depth down with the board's DISPCLK; a shallower raw
candidate can use the retained cap even when the first DSC candidate chose
a slower rate. `frl_video_params` gives the HPO FRL video request's
`FrlVideoRequest { audio_packets_line, borrow, hc_active, hc_blank }`.
Lighting runs link_set_dsc_on_stream's FRL order after training: the pipe's
DSC engines, then `hpo_enc401_hdmi_set_dsc_config` (`frl_dsc_start`:
HDMI_DSC_MODE, FIFO compressed-format bits, zero GCP depth, the CVTEM PPS in
VPG generic packets 5-10 with Linux's packet-buffer reuse), then the OPTC
(`OTG_V_SYNC_MODE` 1); stop runs OPTC off, HPO DSC off (`frl_dsc_off`), then
the DSC disconnect and disable. FRL DSC takes the stream depth as its input
(`DscConfig::bpc`, with zero GCP depth); DML21 admits
the compressed stream (`frl_dsc_vectors.txt`, one FRL output per context as
Linux's `max_num_hdmi_frl_outputs`).

DP MST DSC follows amdgpu_dm and DRM on both encodings.
`amdgpu_mst_dsc::compute_link(streams, link, fits, native)` is
`compute_mst_dsc_configs_for_link` with `increase_dsc_bpp`,
`try_disable_dsc` and `set_dsc_configs_from_fairness_vars`: `peak_pbn`
(`kbps_to_peak_pbn`, 1.006 peak, 1.031 8b/10b FEC), `kbps_from_pbn`,
`DscLink { encoding, kbps, slots, max_dispclk_khz }`, `DscStream { sink,
timing, dsc, bpc }` (the stream's depth: its uncompressed bandwidth and DSC
input) and `DscPayload { pbn, slots, dsc }`; `fits` is the topology's
per-hop PBN check and `native` a provisional decoder configuration. At each
complete depth combination, native selection recomputes whole-link fairness
in stable device-slot order with the board's real DISPCLK, then admits every stream's
resulting DSC and plane topology jointly. Actual final `Plan::pipes`
determine the DSC401 shape; theoretical Vmin support grants no permission.
A beside operation whose fairness changes a fixed stream's PBN, slots or
DSC returns `BesideRefusal::DscFairness` for a relight. The no-decoder raw
MST path keeps requested-depth PBN accounting. In
`amdgpu_navi48_mst::dsc`, `dsc_aux_for_port` is
`drm_dp_mst_dsc_aux_for_port` (end device, DP-to-DP virtual-DPCD peer with
passthrough, DP-to-HDMI/virtual sink, `DSC_WITHOUT_VIRTUAL_DPCD` hubs),
`read_endpoint` is `validate_dsc_caps_on_connector` beside the endpoint EDID,
returning `MstDsc { caps, aux, passthrough, end_link_kbps, branch_oui,
synaptics, pcon }` (optional decoder caps retain raw-only PCON endpoints), `port_supports_mode(t, bpc, ..)` is
`dm_dp_mst_is_port_support_mode` at the stream's depth, and `set_rx` is
`dm_helpers_dp_write_dsc_enable` (passthrough 2 before decoder 1; disable
reverse) through `dp_mst_mgr::Manager::remote_dpcd_read/write`. Selection
and offered modes run the fairness search jointly across the branch. Dark
and lit MST alternatives validate all recomputed payloads against the other
ports' streams; a joining payload is never checked beside stale earlier DSC
configurations. Dark alternatives use the same stable device-slot order as
actual selection, even after topology reordering. Complete recomputation uses
each port's raw availability and the new other payloads; only additive raw
admission uses the old remaining path budget. A raw-only joining sink can be
admitted after existing DSC streams shrink. Every offered candidate retains
the current plane geometry and overlays. Candidates are independent proposals, not reservations. Each
end device at the deepest of its depths (`dp_depths` up to
`MstDscContext::max_bpc`, create_validate_stream_for_sink's loop) that the
port and the joint search take; such a stream leaves at that depth
compressed or raw (VC rate, PBN and audio budget at it). A link without any
decoder runs uncompressed streams at the deepest depth its port carries
raw, their PBN sized for the requested depth (`raw_mst_stream`, see "Navi
48 connector max bpc"). A compressed stream's
payload PBN and VC rate come from the compressed bandwidth
(`uhbr_mst_dsc_rate` on 128b/132b). The decoder is enabled before the
payload, the PPS is sent per stream (DIO SDP or HPO GSP11) before unblank,
and teardown stops the stream before clearing DP_DSC_ENABLE. MST DSC streams
keep their LPCM (see audio below). Synaptics routing adds amdgpu's exact
`needs_dsc_aux_workaround` root identity/revision/sink-count gate: only an
immediate root child may fall back to root AUX when DRM finds no decoder.
A root Synaptics Panamera name byte4 high nibble0x50 plus vendor byte0x50e
0x5a overrides routing to root AUX even through a cascade. Invalid topology
routes and unavailable identity never authorize a workaround. The retained
`MstDsc::synaptics` policy applies only when that root gate is true and the
selected decoder's downstream-port byte is not virtual-DPCD value3.
On the first stream, a root name starting `SYNA` executes amdgpu's PRIUS
vendor FIFO sequence (RC command/result/length/offset/data at 0x4b2/0x4b3/
0x4b8/0x4bc/0x4c0), then enables DP_DSC_ENABLE. Each RC command has at most
ten 10ms async AUX delays and requires both the exact inactive command byte
and a zero result; an old result cannot prove an active command complete.
Before the first new vendor write, a successor preflight waits for the
previously observed command byte to become exactly inactive within ten
10ms async delays; a changed command or AUX failure refuses it. GPU reset
alone never proves completion of an external hub command. A busy hub remains
untouched and journalled; only a new confirmed-idle probe or an independently
proved hub reset may start a fresh vendor sequence. No automatic GPU-reset
loop is used to try to reset the external hub. Other streams
enable without resetting the shared FIFO, and disable leaves the shared
decoder enabled while any sibling payload is retained. Native link-active
input comes from retained payload/transaction ownership, not `link.owner`
(which is installed before first-stream DSC setup).
`MstLink::dsc_change_pending` journals DSC work before the first AUX/vendor
write. Only complete sequence and enable readback clear it; returned error
or future cancellation retains the link and refuses payload changes or
partial teardown until whole-device reset. A failed decoder enable cannot
start a compressed payload. The existing teardown removes its payload and
stops its frontend before last-stream decoder disable.

`amdgpu_navi48_mst::dsc::pcon` owns a detailed virtual-DPCD HDMI endpoint's
converter0x80..83 capability, validated HDMI EDID/HF DSC fields, LPCM budget,
and autonomous post-training state. The route must be exactly that virtual
end port; a shared non-virtual root decoder grants no per-endpoint PCON
policy. `Pcon` is retained even when `MstDsc::caps` is None: missing DSC
cannot bypass downstream raw limits. Converter MAX_ENCODED_LINK_BW_SUPPORT,
endpoint Max_FRL_Rate, post-training bandwidth, and DSC_Max_FRL_Rate are
intersected independently for raw and compressed output. Current source-
controlled mode (0x305a bit3) is refused. FRL requires readable status,
TX-ready0x303b, no autonomous training in progress0x303c, a nonzero trained
rate0x3036, and training-finished for regulated autonomous mode. Like Linux,
a reported bandwidth does not depend on FRL_MODE (some converters clear
that bit); a confirmed active TMDS fallback instead uses the converter's
TMDS clock, HDMI EDID clock/depth and RGB/4:2:0 constraints. Unknown, training
or source-controlled output grants no usable FRL budget. This owner never
starts source-controlled training or programs a PCON encoder/PPS override.

Converter DSC passthrough additionally requires its DSC_SUPPORT passthrough
bit and valid endpoint HDMI DSC/rate caps; otherwise its ordinary DP
decoder may decompress only when the downstream link carries the result
raw. A passthrough endpoint uses HDMI DSC slice/bpp/VIC/chunk rules and
FRL capacity (including supported LPCM), then retains a DP source config
(`DscConfig::frl` None). The selected PCON's DP_DSC_ENABLE passthrough mask0x02
and matching readback are used; ordinary DP decoder mask0x01 and upstream peer
ordering remain with their owners. A known PCON endpoint cannot acquire
the shared Synaptics root FIFO policy merely from the primary branch OUI.

`amdgpu_mst_dsc::compute_link_constrained` adds independent raw permission
and an optional downstream DSC `BwRange` before the existing whole-link
fairness search. Initial raw allocation, maximum compression, fair bpp
increase and try-disable-DSC all respect that contract; final bpp/PBN cannot
escape it. Converter decoder precision also aligns every constrained bpp
candidate to the advertised increment. A converter that requires compression stays compressed even
when the source DP link has ample raw bandwidth. Unconstrained streams keep
the Linux fairness arithmetic and order. Native `compute_endpoints`, raw
choices, reserved-payload alternatives, dark/lit offered modes and final
link normalization use the same endpoint contract and complete plane/DML
admission. Fixed streams retain their payload, DSC and PCON snapshot; a
changed endpoint contract requests a relight before any fixed owner changes.

`MstStream::pcon` retains that selection's snapshot for raw and compressed
streams. Activation queries current state under the existing ColdBoot/OWNER
exclusion before any source/link writes and refuses a configuration the
current output cannot carry. Monitor service refreshes endpoint proposals
without changing live payloads, reports only the affected stream on a known
loss of downstream capacity, and readmits dark outputs as autonomous training
finishes. `MstLink::endpoint_query` journals a status request before its
first AUX transfer; complete reply or NAK clears it, while transport failure
or cancellation retains the session and refuses reuse/partial retirement
until source reset/reprobe. Fresh status still must be proved after reset;
GPU reset itself never proves completion or training of the external PCON.
No IRQ-safe lock crosses await and no host-controlled PCON training is
silently substituted for the autonomous contract.
`modeset_display_mode` and `modeset_displays` select, admit and light again
(at most `VERIFY_ROUNDS`) when the first display reports `LinkReduced`; a later
display's reduction is returned in `Configuration::failed`, and the monitor
leaves that output unconsidered so its next pass relights the configuration.
`retrain_modeset` journals the published modeset in flight before its first
stop. Success clears the record. A refused retrain (`Link`, `LinkReduced` or
a training refusal) whose timing state is again the one recorded after the
link stopped resumes as ordinary teardown at `TeardownStep::Timing`; the
monitor then withdraws writers, retires timing/planes, releases surfaces and
relights against the verified link. Any other failure or a dropped retrain
stays in flight and blocks replay. A confirmed CR, EQ or
link-loss failure whose idle exit is proven leaves the owner in
`DpLinkRefused`, retaining the plan. Only `stop_dp_link` may follow: as in
Linux's retries, the sink is put in D3 and the PHY disabled before the next
setting re-enables it. Any other training failure still quarantines. There is no
alternative-mode fallback yet. The first clock request (clamped to
each minimum) starts PMFW so admission can read live levels. The admitted
plan's DISPCLK/DPPREFCLK are then requested, and the pipe DTO gets its DPPCLK
and pixel clock. Planes are retired, the HUBP is powered and the surface is
staged and filled row by row by `fill(y, row)` while fetch is stopped. Then
memory, timing (with the plan's global sync), blank, DPP, MPC, requestor and
deadlines are prepared before the PHY is enabled, trained, given its frontend
(stream index = pipe), started on black video and switched to scanout.
Inherited GOP consumers must already be retired; the clock owners refuse
otherwise. A returned failure in the per-pipe activation attempts the bounded
abort described below; uncertain owners stay retained. `stop_modeset`
reverses a success down to a disabled PHY with timing and planes retired; the
surface allocation remains bound to its pipe.

Native HDMI connectors expose DRM's standard `"color format"` enum:
`AUTO`=0, `RGB`=1, `YUV 4:4:4`=2, `YUV 4:2:2`=3 and `YUV 4:2:0`=4.
AUTO preserves the HDMI helper policy: RGB first, then declared 4:2:0 if RGB
cannot fit or the mode is 4:2:0-only. Explicit requests retain that encoding
through depth fallback, final admission, offered-mode filtering and relights;
unsupported sink/mode combinations fail. GETCONNECTOR lists timings admitted
under any implemented HDMI format so format+mode can be selected atomically.
CTA extension YCbCr 4:4:4/4:2:2 bits gate those outputs. 4:4:4 deep color additionally
requires HDMI VSDB `DC_Y444` and the matching RGB `DC_30bit`/`DC_36bit`; 4:2:2
permits 8/10/12 bpc independently of deep-color bits (HDMI 1.3 §6.5), within
`max bpc`. 4:2:0 uses its independent HF-VSDB/HF-SCDB deep-color flags and
Y420VDB/Y420CMDB mode maps. VIC 1 remains 8 bpc. 4:2:0-only modes never become
RGB/444/422 under an override. 4:2:2/4:4:4 DSC remains refused; native DSC is RGB.

`Selection`, DML `Mode`, OTG `Request`, `BlankRequest` and `MpcApplied` carry
`amdgpu_hdr::PixelEncoding`. Plane-layout geometry retains only the derived
4:2:0 flag. DML simple 4:2:2 and 4:4:4 share uncompressed scheduling;
native admission binds the full encoding, and 4:2:0 keeps its formatter-width, container and delay
rules. Only native HDMI enables non-RGB output; DP/MST remains RGB.
`hdmi_candidates` enumerates link/depth candidates for `ColorFormat`.
`frl_carries_in`, `frl_link_in`, `frl_video_params_in` and
`ColdBoot::start_frl` use the typed actual encoding. The bool FRL helpers remain
RGB/420 compatibility wrappers for existing reference vectors.

TMDS remains preferred where it carries the requested format. RGB/444 scale
the character clock with depth; 4:2:0 halves pixel rate before that scaling;
4:2:2 retains the full pixel rate and uses an 8 bpc PLL/deep-color resync carrier
while preserving the stream's actual FMT/GCP depth, with deep-color enable off.
FRL capacity uses 2×bpc for 4:2:2, 3×bpc for RGB/4:4:4 and 1.5×bpc for 4:2:0. Its encoder
counts horizontal pixel pairs for 4:2:2/4:2:0, uses pixel format 1/2 respectively,
and only 4:2:0 uses the FIFO 4:2:0 format. 4:2:2 deep-color enable stays off.

OPP programs the actual pixel format, chroma-filter mode and bypass fields;
non-primary ODM segments request the extra left chroma pixel for 4:2:2/4:2:0.
OPTC programs format 0/1/2 for RGB/4:4:4, 4:2:2 and 4:2:0. MPC output CSC and black
color follow the selected YCbCr colorspace (601 below SDTV pixel-rate cutoff,
709 above it, or the requested supported colorimetry). "Broadcast RGB" affects
RGB only. AVI Y bits signal the actual encoding. Startup and later live checks
verify the complete retained format/depth/DSC state and detect drift before
publishing video or allowing flips. Failure after writes retains the owner.

`OutputFormatRequest`/`OutputRoute` and `output_formats_supported` validate the
prospective native HDMI outputs before atomic/SETCRTC mutation or pins,
including TEST_ONLY. They combine actual plane geometry, requested depths,
final native DSC shape and memory admission, with at most one FRL encoder.
The read-only board SoC snapshot survives all CRTCs becoming dark. Prospective
routing removes disabled streams and remaps observed unchanged DP/MST sibling
reservations to their new CRTC, rather than counting old routes twice. A new
unobserved DP/MST link configuration or missing board inputs is refused.
The connector's requested format survives publication/reshape and changes
relight its display. Non-HDMI connectors do not expose this property.

FRL audio admission/training fallback reserves the highest valid SAD rate and
channel count using Linux's capacity helper (layout 0 at 576 lines or fewer).
`Selection::audio` retains valid LPCM and compressed SADs (`frl_audio_info`);
sinks without valid LPCM use silent video. The DTB pixel DTO and
HDMISTREAMCLK retain full pixel rate independent of component depth. Physical
acceptance remains open.

`amdgpu_frl_training::poll_status` handles live SCDC FRL_Start, FLT_Update
and Source_Test_Update requests as Linux's `hdmi_frl_poll_status_flag` does.
`FrlStatusIo::current_ffe` supplies the last acknowledged FFE level; requests
advance it modulo four and apply the source-test de-emphasis/pre-shoot flags.
LTP3 is left unchanged outside FLT_no_timeout tests. Each W1C acknowledgement
clears only its handled flag after source work succeeds. An ordinary retrain
request returns `true` with FLT_Update still pending, so cancellation before
retirement cannot lose the request. Native DDC failures propagate.

`FrlLinkUp` retains `training` and `lane_set` alongside per-lane patterns.
Native pattern/FFE controls accept the selected display's stable link or live
FRL video/scanout, verifying its PHY, encoder, clocks and stream route. Live
updates keep both retained link/video records consistent. `UpdatingFrlLink`
holds ownership across a firmware command; cancellation blocks reuse and a
command/readback failure enters `Failed`. Video, scanout and allocations stay
retained. `ColdBoot::display_frl_current_ffe` checks ownership/readback before
returning the acknowledged level. Source tests may leave the link emitting
patterns while timing and memory fetch remain owned.

`ColdBoot::check_modeset` checks HPD before any FRL SCDC access and returns
`Health::FrlRetrain` for an ordinary sink retrain request. The platform monitor
polls at 200 ms while an FRL display is lit (one second otherwise, with HPD IRQ
wakeups for both). Retraining uses full writer withdrawal and configuration
retirement before fresh admission and bounded FRL training/rate fallback;
siblings may briefly blank. This path does not reset quarantined native owners.
Source-test-only updates preserve the running configuration. Hardware behavior
remains unvalidated.

`ColdBoot::begin_modeset_teardown(m, unplugged)` records teardown intent without
hardware access, before an async CPU-writer withdrawal. `stop_modeset` and
`unplug_modeset` also begin it automatically. Per-pipe progress stays in the
retained owner across errors and dropped futures. `display_teardown_status`
returns `TeardownStatus { next: TeardownStep, in_flight, activation, unplugged }`:
audio, scanout,
video, protocol-specific SCDC/payload/frontend work, link, timing, optional
DSC clock, planes, then Complete. Only successful steps advance, with no
await between completion and recording it. A resume must carry the original
modeset's scanout address/stream/frame witness and teardown parameters;
unplug intent can be upgraded but never downgraded. Completed phases are
not replayed. TMDS/FRL sink cleanup keeps its existing best-effort SCDC policy.
MST link handover/detach runs only after video, payload and frontend retirement.

The unfinished operation still performs all native state/authority/hardware
checks. A returned transient preflight rejection can be retried; native failed
owners remain blocked. Cancellation during CPU withdrawal can resume, since no
native phase has started. Once a native phase starts, a dropped future leaves
`in_flight` set and replay is refused, including compound SCDC/MST work without
a single native completion witness. This does not reset quarantined hardware
or recover arbitrary partial activation.
Completed progress is historical, and requires the owner still to be in
PlanesRetired; fresh CPU/hardware proof remains mandatory for surface release.
High-level activation/retraining rejects incomplete teardowns, and a new
activation clears only that pipe's completed progress.

Before per-pipe activation starts (after shared/pipe-clock preparation), the
owner records an activation with no scanout witness and `in_flight = true`.
Success clears that record and returns the normal `Modeset`. A returned error
clears only the in-flight bit and attempts `abort_modeset_activation(pipe)`;
the original startup error is returned whether cleanup succeeds or fails.
`display_teardown_status(pipe).activation` identifies unfinished startup
cleanup, including a failed pipe missing from `Configuration.displays`.

`ColdBoot::display_modesets()` returns the device owner's copies of completed
Modesets. Each actual startup witness is retained synchronously before another
pipe can start or platform adoption can suspend. Offered-mode and successful
retraining updates refresh that record. Successful native stop/unplug removes
only its pipe; failed/cancelled teardown keeps the handle. These are historical
ownership records, not fresh link/fetch health or permission to reclaim memory.
New single/MST/multi-display configurations reject while any record remains.
This prevents a dropped configuration or exited monitor from losing completed
streams even if the caller's temporary vector disappears.

At the next monitor pass, missing caller handles are restored from these records
and scheduled for ordinary teardown, including CPU withdrawal and fresh surface
release. All conflicting caller records are rejected before copying any handle;
existing siblings are preserved. Recovery never clears another pipe's pending
activation, native failed state or cancellation marker. A cancelled native phase
can still block the entire owner; the retained handles remain available for
diagnosis and eventual reconciliation/reset.

`ColdBoot::display_sst_outputs()` retains physical DP/HDMI connector EDIDs and
independent timing lists from the latest `modeset_displays` probe, including
disabled or unadmitted sinks. Dark timings must pass native link/format/depth/DSC
selection and full joint DML beside every running stream. Four occupied pipes or
an already occupied FRL encoder reject another candidate using that resource.
A preferred mode which cannot fit does not hide fitting EDID alternatives.
These lists reserve no resources; enable still runs full configuration admission.
An all-off/no-lightable-mode configuration returns an empty `Configuration` after
querying board clock limits, without active-display floors, pipe clocks, link
startup or scanout allocation. Valid EDIDs survive an admission/startup error;
failed probes do not retain the former monitor's inventory.

KMS publishes a connected dark physical sink's EDID and admitted modes without
inventing a CRTC mode or framebuffer. Base or extension EDID changes invalidate
old requested/offered timings. Disable intent survives same-connector replug;
HPD loss removes the public inventory, and HPD rise on a disabled port requests
reprobe/re-admission even with no active CRTC. This uses the existing whole
configuration relight policy, which can briefly blank connected siblings.

Startup checkpoints the inverse of each completed link, frontend, video and
scanout phase before the next operation can suspend or fail. This covers TMDS,
legacy DP SST/MST, UHBR and FRL: TMDS/FRL link completion starts cleanup at SCDC,
DP training at Link, legacy SST frontend at Frontend, and video at Video.
TMDS/SST/UHBR/FRL scanout completion starts at Scanout, so an audio preflight rejection
does not strand live fetch. Audio is not stopped unless it actually completed;
successful audio is the final startup operation and returns a normal Modeset.
Retraining an already published Modeset does not create or change an activation
record. UHBR retraining stops audio before scanout and starts it again after
training/video/scanout, filtering capabilities against the newly trained link.

TMDS also records `TeardownStep::PreLinkScdc` before its first SCDC transaction.
A returned SCDC error or subsequent native-link preflight rejection therefore
restores legacy TMDS configuration before retiring timing and planes, without
attempting to stop a link that never completed startup. The sink write keeps
the existing best-effort policy; native state and fresh release guards remain
binding. Completed link startup replaces this obligation with the normal SCDC
then Link cleanup path. Cancellation still retains `in_flight` and refuses replay.

Native Navi48 protected output remains unsupported. KMS exposes neither Content
Protection nor HDCP Content Type, and the native owner creates no DTM/HDCP TA
session. Crypto helpers and HDCP exclusions in retirement safety contracts do
not authorize protected scanout. Firmware, protocol, credential authorization,
protected-buffer isolation and end-to-end validation are tracked separately in
[`navi48-protected-output.md`](../research/navi48-protected-output.md); properties
must remain absent until a supported authenticated and encrypted path exists.

MST checkpoints trained/attached link ownership at Link, the frontend at
Frontend, completed payload allocation at Payload and black video at Video.
Cleanup removes the payload before detaching the frontend/link, preserving
other streams and handing over shared-link ownership when needed. An incomplete
payload transaction blocks every cleanup step, even when native state looks
settled; the retained payload marker described below is independent of the
per-pipe activation/teardown journal.

The abort unwinds these checkpointed phases through the normal native stop
operations, then retires timing (including DSC disable), optional DSC clock,
planes and `TeardownStep::Release`. Without a checkpoint it starts at timing,
so stopped staging or a training refusal whose link was successfully stopped
can still be reclaimed. No successful Modeset/scanout witness is manufactured.
Each stop checks current native ownership and hardware; a previous checkpoint
cannot override a subsequent operation's failed or in-flight state. A scanout
underflow whose native recovery returned to black video can unwind from Video.
Contradictory hardware and failed fresh checks retain the record and uncertain
allocations.
Completed phases survive returned errors; success clears the activation only
after release. The caller must keep the activation unpublished to CPU writers
and other engines, with the same exclusive ownership as `modeset_display`.
Both require withdrawal and draining of any CPU views from earlier surface
incarnations before starting activation, including retained same-geometry
buffers that a low-level caller chose not to release after its previous stop.
An unknown/non-activation pipe is Invalid. Dropping startup or an abort phase
leaves the in-flight marker set and blocks replay, even if the native state
looks reusable during a compound operation or retry delay. No reset or
recovery of cancelled startup, incomplete MST payload transactions,
uncheckpointed active work or shared-clock failure is
implied. Models cover abort phase faults/cancellation, every supported
checkpoint's cleanup suffix, sibling isolation and native staged/live retirement
through fresh release.

The monitor records intent before draining CPU views, publishes the retiring
CRTC inactive, and retains its Modeset until teardown and surface release both
succeed. A later pass resumes recorded teardowns before ordinary health checks
or MST notification service, even if DRM has since asked to reactivate. It
finishes retirement before considering a fresh relight. Console withdrawal
never selects another retiring pipe. Errors still stop the spawned monitor;
explicit resumes and cancellation recovery do not bypass native quarantine.
Pending activation aborts run before topology/health work, and successful
cleanup makes the output eligible for relighting. Preferred-mode fallback and
the benign NoSink/Link path are suppressed while any cleanup remains pending;
they cannot discard an unfinished activation or silently retry it.
Models cover every protocol's step ordering, rejection/cancellation at every
step, request identity, sibling progress and unplug upgrades. Physical
transition/recovery validation remains open.

Alternative DP timings now carry their actual DSC shape into joint DML
admission, computed with the board's DISPCLK limit. After link fallback, the
configuration selection would produce must fit the trained link; advertising
a smaller bpp which the subsequent selection would not use is not allowed.
Successful legacy/UHBR retraining re-admits the previous offered timings beside
the retained sibling streams, always preserving the actual running timing.
The device's retained Modeset and KMS publication both receive the refreshed
list. A queued request for a removed timing is discarded; valid requests and
the running CRTC remain. This neither reallocates scanout nor clears native
failure/cancellation quarantine.

Before training, the modeset enables the connector's HPD block, as Linux's
interrupt-mode HPD GPIO and `enable_hpd` do: the pad's DC_GPIO_HPD_MASK bit is
cleared and DC_HPD_EN set. The board path's one-based selector names
GPIO_HPD_n, served by block n-1 of DCN401's four. A path without a selector
still lights. `hpd_sense` reads DC_HPD_SENSE_DELAYED, the debounced bit
Linux's `dal_hw_hpd_get_value` reads. It is Busy while the pad is GPIO-owned
or the block disabled. `dp_link_status` reads DPCD 0x202..0x207 over AUX for
the link the owner carries (trained, frontend, video or scanout state). No
register is written and the owner state does not change on failure. Following
`dp_parse_link_loss_status`, a link is locked when every trained lane holds
CR, EQ and symbol lock with interlane alignment. It counts as lost only when
it is unlocked and SET_POWER reads D0. `stop_unplugged_dp_link` stops a link
without the sink D3 write, and only while the debounced HPD is low.

`check_modeset` checks hot-plug first, so an absent sink gets no AUX traffic,
then lane lock, then the scanout. It reports `Running(frame)`, `Unplugged` or
`LinkLost`. `retrain_modeset` follows `dp_handle_link_loss`: it stops scanout,
video, frontend and link (sink D3), then trains again down the fallback ladder
from the current setting and restarts video and scanout of the retained
surface. `unplug_modeset` is `stop_modeset` with the unplugged link stop. The
check/retrain/unplug sequencing is composed from owner operations tested
individually; no fake covers the composition and no hardware has run it.

A replug is a new `modeset_display` on the torn-down pipe. Surface
preparation may restage an occupied pipe only right after plane retirement
(or the HUBP power-up that follows it), with fresh evidence that no HUBP
fetches. Its own previous staged address may still be pending, because those
buffers stay owned either way. The same geometry reuses the front, back and
cursor buffers, re-cleared.
A new geometry allocates fresh buffers and parks the old surface (front,
back, cursor) until explicit release.
A later request for a parked geometry on the same pipe reuses that surface,
so switching among a sink's offered modes retains at most one surface per
distinct geometry rather than one per switch. The platform monitor instead
drains CPU views and calls `release_display_surfaces` after successful teardown,
so replug and mode changes do not accumulate these allocations. Direct callers
can retain buffers for reuse until they explicitly perform the same protocol.

`scanout_access::unsafe snapshot(read)` captures a CPU mapping/geometry and
an epoch lease under the same short IRQ-safe lock that
`scanout_access::replace(change)` uses to replace it. The returned `View<T>`
holds no lock while pixels are accessed. It is !Send and holds a scheduler
preemption guard, with IRQ delivery unchanged; it must not span a yield or
await. Pointer/framebuffer values must not escape their lease and their
destructors must not access the mapping. Drop executes MFENCE (x86_64) or
DSB SY (aarch64), between compiler fences, before releasing the epoch and
preemption guard. This drains the originating CPU's WC writes and device
reads; it does not replace HDP/PCIe flush or display fetch retirement.

The fb layer replaces generic mappings through this gate and leases
`FbWriter` fills/blits, cursor snapshots and status-panel writes. DRM fallback
copies lease the query hook's mapping through the last copied row, dropping
the lease before flushing. `query_scanout` alone remains a metadata snapshot,
not lifetime authority. Raw `FbScanout::framebuffer` callers must use the
same lease or independently retain the backing; the early boot console
retains its permanently reserved boot range. Native surfaces are not exposed
through fbdev mmap. A stale pull adoption revalidates the current publication;
failed replacement/restoration clears the generic mapping when no boot mapping
is available, so cached writers see an empty view rather than a dangling one.

`scanout_access::wait_retired().await` cooperatively drains all replaced
epochs, including earlier flips, without waiting for writers on the current
mapping. Cancellation retains outstanding epochs. Navi48 withdrawal waits
after moving/clearing the mapping and before teardown. Both platform flips
and the presenter publish and drain while still holding the async display
owner lock, before another presenter can overwrite the former front as its
back buffer. Back-buffer acquisition and native presentation also drain a
previous cancelled wait before reuse. This proves CPU access completion only;
it neither serializes overlapping pixel writers nor authorizes VRAM reuse.
The legacy DCN314 teardown also drains after withdrawing its shared fb mapping
and before returning to the caller that owns the scanout reservation.
Epoch/cancellation and framebuffer-withdrawal regressions run in QEMU on both
architectures; physical display transitions remain unvalidated.

`amdgpu_navi48_kms` publishes the lit sink as KMS state on the registered
amdgpu card. KMS state is attached on first publication; until then every
amdgpu DRM ioctl fails as before. The state is one CRTC (1), one encoder
(2, TMDS type, as amdgpu_dm reports DP) and one connector (3) whose type is
the lit sink's (DisplayPort or HDMI-A); an unplug keeps the last type.
The card's `NativeOutput` carries the sink's base EDID block, which
GETPROPBLOB returns verbatim, and the exact DRM timing from the DCN
`Timing`. That timing has the porches and sync widths, rounded refresh, sync
polarity flags, and type PREFERRED|DRIVER. GETCONNECTOR and GETCRTC report
it instead of the synthesized timing. The connector also offers every other
timing in `Modeset::modes`: the sink's EDID modes in Linux's
drm_edid_connector_add_modes order (`edid_timings`: detailed timings of the
base block then the CTA-861 extensions, standard timings that VESA DMT
covers, established timings, then CTA short video descriptors through the
VIC table; `narf_edid::modes` carries Linux's tables) that fit the trained DP
link or a TMDS depth and that DML admits at the current clock levels, at
most sixteen. Interlaced and pixel-repeated modes are left out, as are
standard timings that need CVT/GTF synthesis. The HDMI AVI InfoFrame still
sends VIC 0: a CE VIC would make the sink expect limited-range RGB, which the
pipeline does not output. Only the
EDID's first timing carries PREFERRED; the running timing is listed first and
is the CRTC's mode. SETCRTC with a mode is refused (EINVAL) unless the mode's
clock and geometry equal an offered timing.
The Navi48 card is DRIVER_ATOMIC: its KMS publisher sets
`Card::native_atomic`, so `SET_CLIENT_CAP(ATOMIC)` and `DRM_IOCTL_MODE_ATOMIC`
(previously VirtGPU-only) run the bridge's native atomic path, as Linux
amdgpu always offers atomic; CURSOR_PLANE_HOTSPOT stays VirtGPU-only.
Navi22's native card still uses legacy KMS.
An atomic MODE_ID blob is held to the same gate (`accepts_mode_blob`, at
check time, so TEST_ONLY probes see it). Cards without native outputs are
unaffected. A DRM client switching the CRTC off (SETCRTC without a
framebuffer, or an atomic commit changing ACTIVE) records the request with
`platform::request_display_active`; KMS shows the CRTC disabled with the sink
still connected. The display monitor converges on its next pass: off
withdraws the scanout and native presentation and runs `stop_modeset`, and
no plugged sink is lit while off; on (SETCRTC with a framebuffer, ACTIVE=1,
or the last DRM file closing, as drm_fb_helper restores the console) lights
the sink again through the normal modeset. The request is level-triggered,
so an off/on pair between passes does nothing. Setting another offered mode
(SETCRTC, or an atomic commit changing MODE_ID) records it with
`platform::request_display_mode`. The monitor then withdraws the scanout,
runs `stop_modeset` and relights through `modeset_display_mode`, which
selects that timing when the sink lists it and it fits, else the preferred
one. If the requested mode fails to light, the preferred mode is lit and
the request cleared. The last DRM file closing returns to the preferred
mode. Mode changes are therefore asynchronous to the ioctl (the next monitor
pass, up to a second). The teardown sequence now has its own progress and
fault/cancellation models; partial activation recovery remains open. Unplug (and `stop_modeset`)
publish the connector disconnected, with no modes, no EDID, and no mode
accepted. The CRTC is disabled with its framebuffer cleared, and open
clients keep their GEM and framebuffer objects. DRM_IOCTL_VERSION reports
amdgpu 3.0.0, the base ABI with no render feature level. This keeps Mesa's
radeonsi from driving render ioctls the native driver does not implement.
Presentation goes through the back buffer and a latched flip (see live
updates above), and flip events stay software-paced at the real refresh
rate.

Every native plane (primary and overlay: DCN4's planes are all
DC_PLANE_TYPE_DCN_UNIVERSAL) lists `amdgpu_navi48_kms::PLANE_FORMATS`:
amdgpu_dm's DCN4.0.1 order (`amdgpu_dm_modifiers::DM_PLANE_FORMATS`:
rgb_formats, NV12, P010, the FP16 orders) less RGBA8888: Linux lists
RGBA8888 but its actual `fill_dc_plane_info_and_addr` switch returns EINVAL
for it. All four 16-bit UNORM orders (XR48/AR48/XB48/AB48) are supported:
HUBP and CNVC format 26, BGR HUBP crossbar for XB48/AB48, and per-pixel
alpha for AR48/AB48. Their eight-byte pixels use DML's 444_64 source and
the FP16 scaling limits, with normal sRGB input transfer/color handling.
The retained input conversion/color/GAMCOR fixtures include those orders and
explicit RGBA8888 refusal vectors. The overlay planes, plane properties, placement, SETPLANE, tiling and
4:2:0 planes are described in "Navi 48 plane scaling and overlay planes".
ADDFB2 takes a format on a card whose `plane_formats` list it, with Linux's
pitch and dumb-object size checks (a card without native planes keeps
XRGB8888/ARGB8888/RGB565); `drm::card::PixelFormat` knows the formats and
their `cpp`. SETCRTC and atomic commits (TEST_ONLY included) also require
`amdgpu_native_kms::display_admits_format(display, connector, mode, fourcc)`:
a format of the depth the display's offered timings were admitted at needs
nothing more; another depth is admitted by DML against the running
configuration (`platform::display_admits_format`), which needs the display
lit on the same connector and timing, else EINVAL. PAGE_FLIP keeps the
format (EINVAL across formats). A committed framebuffer records its format
with `request_display_format`; a running display scanning another one is
relit in it by the monitor, like a mode request, and a failed relight
returns every display to XRGB8888 with its preferred mode, as does the last
DRM file closing. `amdgpu_native_kms::present_frame` takes the framebuffer's
fourcc: a frame in the scanned format is copied as packed words into the back
buffer; one in the requested format waits for the relight and presents (or
completes) after that monitor pass; others complete at once. The console and
the CPU-copy fallback stay XRGB8888 only (`scanout_framebuffer` refuses
other surfaces). Format modifiers are described in "Navi 48 plane scaling
and overlay planes" (GFX12 modifiers); amdgpu answers
`DRM_CAP_ADDFB2_MODIFIERS` = 1. No hardware validation of these formats
exists.

`platform::spawn_display_monitor` runs after the boot-time native modeset
(`amdgpu.native_display`). It enables HPD on every routed DP port, then runs
a pass at least once a second. Between passes it waits in
`amdgpu_navi48_dispatch::wait_hotplug`, which returns early on a DCN HPD or
HPD-RX vector or lost IH vectors, never sooner than 50 ms after the previous
pass. After enabling a port's HPD block the monitor arms its interrupt
(`Otg::enable_hpd_irq`: a stale event acknowledged, DC_HPD_INT_POLARITY set
away from the current debounced sense, DC_HPD_INT_EN, plus DC_HPD_RX_INT_EN
for DP, as amdgpu_dm_hpd_init does). On an early wake it acknowledges every
port's raised event (`ack_hpd_irq`: a plug/unplug edge as Linux's hpd0_ack,
strobing DC_HPD_INT_ACK and re-arming the opposite polarity; a short pulse
with DC_HPD_RX_INT_ACK) before the pass reads the sense. The arm/acknowledge
register sequences are model-tested; delivery of DCN vectors through the IH
is not proven on hardware, and the once-a-second poll stays the fallback. Each pass is `monitor_display`: with a modeset running it calls
`check_modeset`. A lost link is retrained with the surface still published.
On unplug the scanout is withdrawn (the console returns to the boot
framebuffer) and the modeset is torn down. With no modeset, any routed port
sensing HPD high is lit by a new `modeset_display`, which publishes the
surface again. An owner error stops the monitor, leaving the owner where it
stopped.

The platform `modeset_display` publishes the live surface only after
activation succeeds, through `amdgpu_dcn_display::publish_external`. The
published `GenericFb` is the surface's bus-physical BAR address, visible size
and byte pitch (`Otg::scanout_framebuffer`, which requires `ScanoutRunning`
for that pipe and the owned surface). The fb layer's existing observer moves
the console onto it. Adoption maps the published physical range
(write-combining on x86_64, Normal-NC on aarch64) and installs that kernel
mapping, cached per range and never unmapped. DRM presentation (the existing CPU copy of
a dumb buffer into the live scanout) reaches an adopted external scanout
through that mapping: the fb hook reports it with a kernel-virtual base only
when the console adopted exactly the published surface. Nothing new is offered
to userspace mmap, and the boot framebuffer keeps its fbdev-only behaviour. The fb layer previously stored
the physical address itself, which `GenericFb::framebuffer` dereferences, for
both AMD external scanouts and the boot framebuffer restore. The scanout
carries a flush: CPU writes through the BAR
pass HDP, so `GenericScanout::flush` calls `flush_active_scanout`, and the
platform hook try-locks the owner and issues the native HDP flush
(`Otg::flush_scanout_writes`). It never waits; a skipped flush still drains,
only later. The policy is single-buffered front-buffer rendering: tearing is
possible and no vblank synchronisation is claimed. The platform `stop_modeset`
withdraws the scanout first, clearing the flush before observers run, so the
console returns to the boot framebuffer. That range stays excluded from the
VRAM pool for its lifetime and therefore remains valid memory. Teardown waits
for leased fb/DRM accesses to finish; the monitor subsequently releases the
native surface only after the hardware checks above succeed.

Page flips are double-buffered on one pipe. `unsafe Otg::prepare_back_buffer`
(ColdBoot `prepare_display_back_buffer`) reserves a second allocation of the
front's geometry, staged or live. It must translate through the FB aperture,
is cleared and HDP-flushed, and stays retained until explicit surface release.
`back_framebuffer` exposes its CPU view; raw callers must exclude reclamation
for the lifetime of their access.

`unsafe Otg::flip` (ColdBoot `flip_display`) requires `ScanoutRunning`. It
rebinds the deadlines and verifies the live fetch at the current front. It also
requires no held OTG lock, no OTG, pipe-update or flip pending, no MPCC update
lock and no underflow. It HDP-flushes the producer's writes and enters
`Flipping`. Following hubp401_program_surface_flip_and_addr, it writes the back
address (high, then the publishing low; the staged flip type is VSYNC) under the
master-update lock. Completion is no flip pending and `SURFACE_EARLIEST_INUSE`
equal to the new address within the frame-bound timeout, with underflow
watched. The owners must be unchanged. Then every retained report (surfaces,
DPP, MPC, requestor, scanout) is retargeted together, the buffers swap, and the
binding and live fetch are re-verified at the new front. `FlipDone` names the
new front, the now-reusable back and the frame count. Any failure leaves
`Failed`, with both buffers retained because which one is still fetched is
unknown. The platform `flip_display` moves a console that had adopted the old
front onto the new one and drains CPU views before releasing the owner lock.
There is no flip interrupt or event queue yet:
completion is polled. Under DRR the flip also fires the OTG manual trigger
after the lock release (Navi 48 variable refresh).

Live updates have one synchronization policy per writer. The front's
`upload_surface` stays stopped-only. `unsafe Otg::upload_back_buffer(pipe,
x, y, pixels)` (ColdBoot `upload_display_back`) writes part of one row of the
next frame into the back buffer only while the pipe is `ScanoutRunning` on
its front with a back buffer distinct from it; during `Flipping`, after a
failure or once stopped it is `Busy`, and bounds are checked per row. No CPU
pointer escapes, and the writes reach display through `flip`'s HDP flush. The
kernel console keeps drawing the published front with an HDP flush per
update (a text console may tear). DRM clients own presentation while they
hold the display (`fb_take_for_user`). The platform modeset allocates (or
reuses) the pipe's back buffer. DRM frames for the amdgpu card are handed to
`amdgpu_navi48_platform::present_frame`, a one-slot mailbox drained by a
presenter task that copies the newest frame into the back buffer under the
owner lock and flips. A frame arriving during a copy or flip replaces any
frame still waiting, and the latest always shows. DRM's rule that a client
leaves a submitted framebuffer untouched until a later flip completes covers
the deferred read. A failed flip quarantines the pipe and disables native
presentation. Without a back buffer, frames fall back to copies onto the
visible front. Flip-complete events stay software-paced at the refresh
rate (milestone 5). The presenter glue has no model test; `upload_back` and
flips over a fully staged chain do.

`unsafe Otg::set_cursor(pool, gmc, pipe, (w, h, pixels), (x, y))` (ColdBoot
`set_display_cursor`) shows a premultiplied ARGB8888 cursor on a live pipe.
The size is capped at 64x64, Linux's DCN401 `max_cursor_size`, which also
keeps it out of MALL; DML21 already budgets a 256-wide ARGB cursor per plane,
so admission is unchanged. The first call allocates a retained 16 KiB buffer
inside the FB aperture. Each call rewrites the image there with transparent
padding and HDP-flushes it; an image change is not tear-free, because the
buffer is single.

Programming follows program_cursor_attributes and program_cursor_position:
on every pipe of the stream that carries a plane (the primary's ODM segments
and MPC slices and every overlay's pipes), dcn10_set_cursor_attribute and
dcn401_set_cursor_position, inside mpc1_cursor_lock (`CUR_VUPDATE_LOCK_SET`
of each ODM segment's OPP, whose MPCC tree carries every plane of the
segment; released on every path):
- HUBP: address (high, then low), size, and `CURSOR_CONTROL` with mode 2,
  pitch 64, lines per chunk by width and `CURSOR_REQ_MODE` 1.
- `CURSOR_SETTINGS`: full write of 0x300.
- CM_CUR: mode 2, no expansion or degamma ROM, FP16 1.0 scale, matrix bypass.
- Position, hotspot and `CURSOR_DST_X_OFFSET` per pipe.

The position is amdgpu_dm_plane_get_cursor_position's (a negative origin
moves into the hotspot, at most 63; one 64 or more past the left or top edge
disables the cursor) taken through dcn401_set_cursor_position for each pipe
(`cursor::pipe_position`): past the src widths of the ODM slices before the
pipe (resource_get_odm_slice_src_rect, a 4:2:0 slice one pixel wider), the
MPC bottom-pipe move, then into the pipe's recout space, every part left of
or above either moved into the hotspot, disabled when none of the image lands
in the recout or when resource_can_pipe_disable_cursor finds a plane of
another layer above whose recout (merged with its other slice) contains the
pipe's; then hubp401_cursor_set_position: `CURSOR_DST_X_OFFSET` from the
viewport position (recout to viewport scale) in DCHUB reference clocks over
the horizontal ratio (dc_fixpt_from_ux_dy of SPL's register), the X hotspot
clamped to 255. `CursorApplied::shown` names the pipes enabled; the
live-fetch witness expects exactly those. `move_cursor` (or the non-blocking
platform `try_move_display_cursor`, for pointer pumps) only repositions. A
live plane update re-places the cursor on its new pipes under the OTG lock
(dcn20_update_dchubp_dpp). Stopping scanout hides the cursor on every plane's
pipe under the locks before the planes stop, and drops the report while the
buffer stays retained. Any readback mismatch quarantines the pipe.

`otg::cursor_mode(dce_ip, crtc_enabled, cursor_scale, planes)` is
amdgpu_dm_crtc_get_cursor_mode (`CursorMode::{Native, Overlay}`, the planes
under the cursor as `CursorUnder`, `plane_scale` as dm_get_plane_scale): DCN
4.0.1 (Navi48), 4.2.0 and 4.2.1 and a disabled CRTC always take the native
cursor, so amdgpu_dm neither needs the overlay cursor nor refuses a cursor
over a scaled or YCbCr plane there; other DCN take the overlay cursor over a
YCbCr plane, a plane scaled unlike the cursor in both directions or a hole.
The platform publishes a cursor hook with the scanout
(`amdgpu_dcn_display::publish_external_cursor`, cleared on withdrawal before
observers run). It try-locks the owner, uploads the image once, moves it
afterwards, and hides it with an off-screen move. When the owner is busy it
skips the update but still reports the cursor as handled, so the fb layer
never paints a software sprite into a hardware-cursor surface. The fb cursor
pump uses it for the console pointer whenever the console adopted exactly
the published scanout; on a display whose cursor a DRM cursor plane drives
(see "Navi 48 DRM cursor planes") it reports the cursor handled and leaves
the hardware alone.

Native 8b/10b MST uses `dp_mst_mgr::Manager` over the port's DMUB AUX channel.
`ColdBoot::display_mst_capable(port)` checks DPCD revision and MSTM_CAP before
the platform chooses MST. `start_display_mst` requests/acknowledges receiver
D0 even for empty branches, enables MST/up requests and clears payload tables
once, then probes LINK_ADDRESS/ENUM_PATH_RESOURCES depth first;
`read_display_mst_edid` reads end-device EDIDs through REMOTE_I2C_READ. The
probe uses an explicit stack so its future can run in the display monitor,
bounded to 15 route levels and 64 branches. Clean sessions reuse the snapshot;
dirty sessions can reprobe only after every source owner and payload retires.
The previous snapshot remains available until probe/EDID completion. A
cancelled probe retains the session and refuses replay until physical removal
or explicit streamless manager shutdown. A returned error is no uncertainty:
one before MST is enabled (D0, MSTM_CTRL, the payload-table reset: Linux's
drm_dp_mst_topology_mgr_set_mst failing) shuts the streamless session down
(MSTM_CTRL cleared, the session dropped) and the port stays an SST board
port, as link detection falls back to dc_connection_sst_branch when
dm_helpers_dp_mst_start_top_mgr fails; one in the probe keeps the started
session ready and dirty with its previous snapshot, for the next pass to probe
again, as Linux's probe work only logs. Neither escalates: the platform's
hotplug start (`start_plugged_mst`), a lighting's start (`light_displays`),
`start_mst_route`/`start_mst_route_beside` (whose `Ok(false)` route lights
nothing) and the monitor's `service_display_mst` (an up-request poll,
resource query or live probe) log the failure and go on; the streams on the
port run on. Nor does a refused DSC enable on an MST stream's decoder
(link_set_dpms_on ignores dp_set_dsc_on_rx's result). What reaches
`monitor_displays`' error, and so device recovery, are local display state
failures: source programming (SAT, VC rate, encoders, link handover),
teardown journal faults and transactions left uncertain by cancellation.

`Manager::poll_up_requests` reads at most eight ready up-request chunks per
call without waiting for a new notification. It acknowledges only
UP_REQ_MSG_RDY, leaving down replies and other ESI bits alone. Fragment
reassembly survives idle poll budgets and down-transaction completion;
start/stop clear the previous session's fragments and events. Complete
connection/resource notifications enter `events`, capped at 64. `EventsFull`
leaves the next branch chunk unacknowledged until the caller drains the queue.
Down transactions still consume their own replies while that queue is full.
Truncated bodies fail instead of manufacturing zero-filled status fields.
An event survives failure to send its sideband ACK after ESI acknowledgement.
The ACK goes to the primary branch (broadcast, LCT 1) whichever downstream
branch sent the notification, as drm_dp_send_up_ack_reply(mgr, mst_primary).
`ColdBoot::poll_display_mst(port)` and `take_display_mst_events(port)` expose
this service over DMUB AUX. `service_display_mst` drains before/after polling
and marks known-branch/known-port connection notifications for reprobe. Resource
notifications on connected output ports coalesce into fresh ENUM_PATH_RESOURCES
queries; notification PBN values alone never become admission authority. Replies
must match the requested port and have available PBN no greater than full PBN.
The driver adds its current payload PBN back to the queried free capacity,
including descendant streams on a shared branch hop. Its own allocations thus
do not cause repeated relights. A changed capacity/FEC snapshot requests
reconfiguration. While streams run, `MstLink::reprobe_live` (inside
`service_display_mst`) first probes the tree again, as Linux handles a CSN
without touching unaffected streams: branches with the same GUID and route
keep their `Topology::branches` index (new ones fill vacated indices, then
append; unfilled vacancies are port-less placeholders), every hop's reported
free PBN is credited with the driver's own payloads, and the new topology is
adopted only if every payload's end device is still connected and its PBN
fits every hop beside the others. Adoption reconciles outputs, rereads
EDID/DSC, readmits dark outputs' modes beside the running displays and
clears the dirty mark; the monitor republishes the connectors, and a new
end device's connector takes a CRTC and lights beside the running streams
(`modeset_beside`), as a Linux commit adds its stream. A port with no
stream reprobes in place (`MstLink::prepare`) the same way. When only some
payloads' end devices left (`MstLink::lost`, `MstService::Lost(pipes)`),
the monitor retires just those streams — each payload removed as
drm_dp_remove_payload_part1 removes it: ALLOCATE_PAYLOAD with PBN 0 to the
departed device's branch and its payload-table row cleared, both results
ignored, because the device's branch port is still downstream of the
primary (drm_dp_mst_port_downstream_of_branch walks the port's parents,
which a drm_dp_mst_port keeps for its whole lifetime), so the branch's VC
payload table compacts with the source's and the streams beside it keep
their slots; its DSC decoder is not addressed (amdgpu_dm clears the
disconnected connector's dsc_aux). A payload behind a branch the reprobe
found gone (`MstLink::departed`) has its ALLOCATE_PAYLOAD sent to the
nearest ancestor still connected, at the port the departed branch hung
off, as drm_dp_payload_send_msg falls back to
drm_dp_get_last_connected_port_and_mstb — then services the port again to
adopt the tree beside the streams still running. Only a payload whose
port is off the primary skips part 1 ("not in topology"): the root's HPD
is low (dm_helpers_dp_mst_stop_top_mgr cleared mst_primary) or a live
reprobe found another primary branch (`MstLink::primary_replaced`).
Otherwise (another primary branch, a hop's capacity lost:
`MstService::Relight`) the old topology and routes stay and the monitor
stops all streams using their old routes, reprobes, then relights enabled
outputs.
A cancelled live probe retains the session like `prepare`; a failed one
leaves the old topology, its routes and the dirty mark for the next pass.
Notifications received during queries/reprobe remain queued for the next pass. Unknown branch/port, input-port and disconnected
resource notices are ignored.

`MstLink::resource_query_pending()` reports an incomplete resource-query batch.
The marker precedes the first AUX operation and clears only after every response
has completed. Returned failures and cancellation retain it and the topology,
payloads and session, refusing subsequent payload/sideband transactions, startup,
teardown and session disposal. These uncertain queries require future explicit
reconciliation/reset; an empty source/payload list is not permission to discard
them. Models inject faults before and after every AUX operation on both active
and empty sessions.

`MstLink::outputs` reserves `MST_OUTPUTS` (sixteen) stable slots per port.
Linux bounds MST connectors only by the topology (drm_dp_mst adds one per
output port); what it bounds is lighting: amdgpu_dm's CRTCs are
dc->caps.max_streams, min(pipe_count, stream_enc_count), four on DCN 4.0.1
(four OTGs, OPPs, DIO and HPO stream encoders in res_cap_dcn4_01), and each
manager sources at most `MAX_PAYLOADS` = 4 payloads. Four lit streams across
every port (`modeset::MAX_DISPLAYS`) is the real hardware limit; more end
devices than that are published as connectors and stay dark until a CRTC is
routed to them. Sixteen slots is NARF's fixed table bound (KMS indices and
per-connector requests), not a Linux one. `MstOutputId` includes root
GUID, branch GUID, LCT/RAD and output port; probe vector indices are never
connector identities. Surviving identities claim their old slots before new
devices are admitted. Disconnected slots retain their requests for replug;
new devices use empty slots first, then reclaim absent reservations if full.
Reassignment resets old DRM requests. Replug of the same endpoint preserves
CRTC disable; changed EDIDs (including extensions) invalidate cached modes.
`MstOutput::modes` holds independently admitted timings for a present output
without a lit stream; reprobe clears the list before new admission. Successful
configuration refreshes each dark output against the slots left by running
payloads, its probed available PBN and joint DML admission with all running
streams. Each candidate is an independent possible addition, not a reservation;
enabling several connectors still reruns complete configuration admission.
The list follows EDID order and is bounded to sixteen timings. An all-off
branch queries the board's DPM limits (starting display power if needed), but
does not request an active-display count, clock floors, pipe clocks, payloads
or scanout allocations. Startup failures do not publish new dark-output modes.

`unsafe ColdBoot::modeset_routed(fill, want, crtc_of, mst: &[MstRoute])`
lights board SST/HDMI sinks and the MST branches of any number of DP ports as
one configuration. Each port has its own `MstLink` (manager, topology, payload
table, owner), as amdgpu_dm initializes an mst_mgr per DP connector.
`MstRoute { port, crtcs, want }` names a branch's root port, each end
device's CRTC (`crtcs[k]` for `MstLink::outputs[k]`, None dark) and timing
request; routes name distinct ports. Streams are named by CRTC, never by
pipe: each runs on the head pipe it acquires (`Modeset::pipe`, its owner
slot) and records its CRTC (`Modeset::crtc`); the plane format, planes,
Colorspace/HDR and CRTC color a lighting uses are the CRTC's
(`set_plane_format`, `set_plane_setup`, `set_output_color`,
`set_crtc_color`, by CRTC), the CRTC color recorded on the head pipe before
its scanout starts. The round validates and starts every
branch, scans once, selects board sinks with every MST root excluded
(`select_all`; board port p as CRTC `crtc_of(p)`'s stream at `want(p)`)
and each branch's devices against its own link (its time slots, PBN hops
and DSC fairness), then `route_streams` joins them in CRTC order, refusing
a CRTC named twice on one port or across ports (admission truncates
trailing streams), and runs one clock request, `refine_dsc`, joint
`admit_displays`, `prepare_pipes` and `light` per stream over every port
together. SST connector inventory
(`display_sst_outputs`) excludes the MST roots; dark end devices are admitted
beside every running stream, slots, hop PBN and DSC fairness counted only for
their own port's payloads. `modeset_displays` is `modeset_routed` without a
route. Each round is retried as described for `LinkReduced`.

`unsafe ColdBoot::modeset_mst_displays(port, fill, want, crtcs)` is
`modeset_routed` with that route and no board CRTCs. It lights one
branch's sinks with joint DML admission, RGB at each end device's depth (see
"Navi 48 connector max bpc") and the maximum supported link.
`crtcs[k]: Option<u8>` assigns stable output k to a distinct CRTC, or
disables it. Disabled, unreadable and unadmitted devices
leave gaps; their successors never inherit their CRTC or requested mode.
Each payload must fit the remaining 63 slots and the available PBN of every
connected hop from the sink to the root, after subtracting selected sibling
payloads on each shared hop. Missing, cyclic or ambiguous parentage refuses
admission. Zero PBN is exhausted capacity (including `select_mst` inputs),
never an unlimited/unknown sentinel. Low-level payload adds recheck path budgets
before writes; dark-connector mode admission uses the same path accounting.
Active-stream alternatives remain inside both their allocated slots and PBN.
Add orders the DPCD payload table, source SAT/ACT, ACT handled,
ALLOCATE_PAYLOAD and stream VC rate before video. Remove zeroes the VC rate,
deallocates remotely, updates SAT/ACT and compacts later payload slots. Physical
root removal skips all remote AUX transactions and waits during removal.
The sink-side steps are best effort as allocate_mst_payload /
deallocate_mst_payload and amdgpu_dm's helpers run them: the payload is
recorded with its VCPI and slots whatever they return. A failed
payload-table write leaves it `PayloadAllocation::Local` and skips
ALLOCATE_PAYLOAD (drm_dp_add_payload_part1 "is OK to fail", part 2 skips a
failed part 1); an ACT that is not handled still sends ALLOCATE_PAYLOAD
(ACT_FAILED is not ACT_LINK_LOST); a failed or NAKed ALLOCATE_PAYLOAD leaves
it `Dfp` (part 2 only logs); each failure is a console line. The VC rate is
set and the add completes. Removal undoes only what was allocated
(drm_dp_destroy_payload_at_remote_and_dfp): ALLOCATE_PAYLOAD(PBN 0) for a
`Remote` payload, the payload-table row for `Remote` or `Dfp`, both results
ignored, ACT unchecked.
The bookkeeping is DRM's: `mst::allocate_slots(payloads, uhbr, slots)` is
drm_dp_mst_atomic_check_payload_alloc_limits (63 or 64 time slots, at most
`mst::MAX_PAYLOADS` = 4 payloads per manager as amdgpu_dm initializes it, the
new payload checked first and then the newest, so `SlotRefusal::{NoSpace,
TooMany}` is Linux's -ENOSPC/-EINVAL) with the lowest free VCPI and
drm_dp_add_payload_part1's next start slot; `release_slots` is
drm_dp_remove_payload_part2's compaction. 3000 Linux sequences of additions and
removals (`tests/dcn401_mst_payload`, the extracted helpers including
drm_dp_dpcd_write_payload and dm_mst_get_pbn_divider) fix the time slots,
refusals, VCPIs, start slots, payload-table rows and ALLOCATE_PAYLOAD PBNs.

`MstLink::payload_change()` reports `Option<MstPayloadChange>`, whose Adding and
Removing variants carry the DIO stream index. The marker is recorded before the
first AUX/source side effect and cleared only after all required steps complete,
without a suspension between completion and clearing. A sink-side failure is
not one (see above): only a source step's returned error (SAT or VC rate,
which Linux's void hwss calls cannot report) and dropped futures retain it,
including before an add reaches `payloads.push` or after a removal empties
that list. It is historical uncertainty, never a retry
or ownership proof. Another add/remove, startup, modeset teardown (including its
link handover/detach), clean/dirty topology preparation, notification polling and
remote EDID reads are refused with Busy while it remains. Session shutdown and
physical removal cannot discard it merely because source-owner/payload lists are empty.
Static request rejection before the transaction starts (such as duplicate stream
or missing payload) leaves it clear and permits a corrected request. Source
completion is still required. No reconciliation or reset of uncertain payload
state is provided. Models inject returned errors and deterministic cancellation
on both sides of every AUX/source operation, checking retained state after
source failures and cancellation, completed best-effort transactions after
sink failures, no replay or sibling mutation, topology/session retention and
successful slot compaction.

The first display trains the link; the others attach and own their own
DIG_FE_MODE=5 frontend selections. When the link owner stops its frontend,
`hand_over_mst_link` transfers ownership to a remaining attached display.
Only the last display stops the PHY; a connected root stays in D0 with its
MST manager enabled, including all-off and empty configurations. Physical
removal drops the manager after its last source owner/payload retires;
`forget_unplugged_display_mst` checks HPD low and performs no AUX access.
Explicit `stop_display_mst` refuses to drop a live owner, payload or incomplete
payload transaction.
Source verification accepts sibling routes being released while still rejecting unowned frontend
selections. Failed transitions retain their owners and allocations.

KMS routing follows Linux: there are `crtc_count()` CRTCs, four unless
pipes are fused (display k is CRTC id 1 + 3k; its stream runs on the head
pipe it acquires, as amdgpu_dm takes acrtc->otg_inst from the stream's
primary_otg_inst: the platform's display k is CRTC k for KMS state,
requests, presentation, vblank clocks and DRM cursors, and `crtc_pipe(k)`
names its head pipe while lit) and one connector per board DP/HDMI port (board ordinal n: encoder
2 + 3n, connector 3 + 3n, all ports, not only four), plus, for every DP port
whose connected sink is an MST branch, a connector for each of its end-device
slots that has held a device (index 32 + 16 port + slot), as drm_dp_mst adds
one per end device it finds; the root's own connector then reports
disconnected. Every encoder may drive
any CRTC (`possible_crtcs` the pool's pipes, 0xf unfused; `amdgpu_navi48_kms::{RoutedConnector,
apply_routed, publish_routed, connector_index}`). A CRTC drives at most one
connector: SETCRTC's single connector (more than one is EINVAL; none keeps the
routing) or an atomic connector CRTC_ID routes it explicitly
(`platform::request_display_route`, `request_connector_crtc`), moving the
connector off its old CRTC and parking a displaced connector so automatic
routing does not relight it elsewhere. Otherwise plugged, unparked connectors
take free CRTCs in connector order and keep them while plugged. MODE_ID and
SETCRTC modes are validated against the connector the CRTC drives after the
request (`display_offers`). Board SST/HDMI sinks and the branch's end devices
light as one configuration (`ColdBoot::modeset_routed`); a running display
whose connector routing changes is relit. The last DRM file closing restores
automatic routing. An all-off DRM configuration keeps connector identities
and requests while the branch remains connected; removing the branch (with
no stream left on it) drops its connectors and their routes. Shared-link loss stops and relights the whole configuration instead
of invoking the SST retrain path. A downstream change that keeps every lit
route is adopted live (`reprobe_live`, above) and republishes the
connectors; a newly appeared end device lights beside the running streams
and a departed one retires only its own stream. A branch plugged into a
board port with no display starts there and its devices light beside the
running displays (see "Navi 48 seamless shared-clock changes"); an MST
stream a DSC fairness change touches is modeset alone. A changed primary branch or
lost hop capacity uses the whole-link stop/reprobe/relight sequence, so
other streams briefly blank. KMS can publish
a newly discovered EDID and independently admitted timings as connected with
its CRTC off (`amdgpu_navi48_kms::Output::{edid, offered}`). These timings reach
GETCONNECTOR and the platform's mode-request gate without setting a CRTC mode
or framebuffer. A missing EDID suppresses the offered timings. Ordinary MST
disable retains previously admitted timings without restarting siblings;
the next configuration/reprobe recomputes admission against remaining resources.
MST DSC follows amdgpu_dm's fairness search (see the DSC policy above).
Cascaded (daisy-chained) branches are one topology: each branch is probed by
LINK_ADDRESS at its own LCT/RAD (`dp_mst_mgr::child_rad`), sideband
transactions for an end device (ALLOCATE_PAYLOAD, REMOTE_I2C_READ, remote
DPCD) go to that device's own branch, end devices across branches share the
link's payload table and the port's stable connector slots, and every hop of a
device's path bounds its payload, dark-mode admission and the DSC fairness
search jointly with the sibling streams crossing that hop. Every connected DP
port whose sink is an MST branch runs MST at the same time, each on its own
link and payload table; their streams share the pool's pipes, the clocks and
DML admission. End devices beyond a port's sixteen slots are not published.

An MST branch that codes 128b/132b runs UHBR MST, as Linux's
decide_mst_link_settings trains MST at the verified cap: the best UHBR rate
on every lane. Selection then counts all 64 time slots (no MTP header slot,
drm_dp_mst_update_slots) with dm_mst_get_pbn_divider of that link, and
payloads start at slot 0 (`MstLink::uhbr`). The first stream trains the link
with `UhbrSettings::mst` on the link's HPO DP link encoder (see "Stream
encoders"; training requires the
manager's MST_EN; stopping leaves the branch in D0); later streams attach to
the owner's `UhbrLinkTrained` record, and handover/detach follow the 8b/10b
rules. Each stream uses the HPO DP stream encoder it acquired, in Linux's order:
`prepare_uhbr_mst_stream` enables and maps it with its timing running blank
(`State::UhbrStreamReady`), the manager adds the payload through
`update_uhbr_mst_allocation` (HPO SAT rows with ACT) and `set_uhbr_mst_vc_rate`
(the recorded `uhbr_mst_rate`: PBN over PBN-per-slot, a 25-bit Y and the
minimum blanking width, matched against Linux's fixed-point code), then
`start_uhbr_mst_video` unblanks it. Teardown (`Protocol::UhbrMst`) blanks
(`blank_uhbr_mst_video`), removes the payload, and only then
`stop_uhbr_mst_stream` disables the stream, refusing while its VC rate or a
SAT row remains. `Siblings::hpo` holds stream encoders and `hpo_links` the link
encoders they ride. UHBR MST LPCM (`Otg::start_mst_audio` on an HPO stream)
uses the stream's APG and endpoint as UHBR SST does, with Linux's 128b/132b
budget (the whole link and the timing's blank width, not the slot share). It
starts only with the manager's completed `slots`, an acknowledged payload and
exactly one SAT row naming the stream at those slots, which the running
audio's checks keep verifying; the plain DP entry refuses it (`Unsupported`).
Legacy MST LPCM uses each stream's AFMT and endpoint as described below.
This path is model-tested only.

`unsafe ColdBoot::retire_inherited_display` retires the legacy DP SST output
the firmware left running. It runs in native dependency order:
1. Blank every DIO stream (a no-op when already blank).
2. Disable each board-routed DP backend with a single routed frontend. A port
   without one is refused in planning before any write, and is skipped only if
   the owner stays reusable.
3. Require every active stream to have been found behind a backend, then
   retire those encoders.
4. Retire planes and every timing generator still running (`running_timing`,
   read-only). Idle or soft-reset OTGs are left alone.

HDMI, HPO and MST output are not retired by it; their live state makes it
fail. The RDNA2 fb boot handoff runs it, followed by `modeset_display(0, black)`,
unless `amdgpu.native_display=0` (on by default). If the modeset then
fails, the GOP no longer scans out and the screen stays dark until a later
modeset; the console's GOP framebuffer remains valid, excluded memory.

Physical presentation on the sink remains unverified.

The port deliberately diverges from Linux where Linux would program something
the hardware cannot honour: it enforces the Tpre > max(Turg, Ttrip) + Tex
prefetch check Linux compiles out (`#if 0`), which matters precisely because
the VM/row stages sit at their quarter-line minimum here; rejects a DISPCLK
needing a DFS divider below 2.0; and rejects register-range overflows DML only
asserts. Plans match exactly except
for +-1 truncation in deep-sleep DCFCLK and the urgent-bandwidth fractions.
DPPREFCLK is the DFS output mode programming uses; Linux's informative copy
can read 1 kHz lower.

`unsafe Otg::blank_dp_stream(DpStream::{Dio,Hpo}(instance)).await` blanks one
of the four native legacy or four HPO DisplayPort stream encoders. Stream
instances are independent of OTG/transmitter routing; this operation never
infers a board route or changes a PHY. Callers must stop CPU scanout writers,
exclude firmware/FAMS and concurrent display, audio/packet, link, clock and
power writers, and retain every associated allocation and translation. The
retained timing owner serializes the operation; active timing/links may remain
running. Invalid instances, contradictory frontend modes/clock enables and
incomplete resets reject before writes.

Legacy DP requests VBLANK-deferred disable and waits for both video enable and
hardware status to clear, including inherited enable-clear/status-set cases.
Only then may it assert steering-FIFO reset and require reset-done. HPO DP
likewise waits for video acknowledgement before disabling SDP and the pixel
and clock-ramp FIFOs, in native order. Video waits have a 150 ms bound and the
legacy reset acknowledgement has a 1 ms bound. An already blank disabled
encoder receives no writes. Final readback checks that frontend enables,
clock selections/enables and reset state were preserved. Stream, link and
timing clocks remain retained; DIO audio/secondary packets remain unchanged.

Success enters `DpBlanked` and records `DpBlanked::{stream,was_active}` in
`Status::dp_blanked`. This is historical video-blank evidence only: it does
not prove sink power-down, PHY/encoder/timing/memory retirement, MST teardown
or HDMI blanking. Subsequent timing, plane and clock operations still require
their own live consumer checks. Cancellation leaves `BlankingDp(stream)`;
errors after beginning the operation enter `Failed`, blocking all reuse until
independent reset. No outcome permits allocation reuse. `unsafe
ColdBoot::blank_display_dp_stream` and the platform wrapper require the
drained GC12/SDMA interrupt proofs and serialize access to the same owner.

`unsafe Otg::retire_dp_encoder(DpStream).await` disables one already blank
native DP frontend. It checks live hardware rather than trusting a previous
`DpBlanked` snapshot. Video, secondary packet scheduling, DIO GSP8–11 sends
and metadata transactions must already be stopped; incomplete FIFO resets
reject before writes. Callers retain all resources, exclude CPU, firmware/FAMS,
display/audio/packet/link/clock/power writers, and independently retire sink/MST
bookkeeping and audio/metadata producers. This API does not perform those steps.

DIO retirement resolves all four backend frontend-selection bitmasks. Every
backend connected to the selected frontend must be disabled first, preserving
legacy SST shutdown order; this initial path also requires that for MST. Live
unrelated outputs are allowed. Unsupported frontend selectors reject before
writes. Native sequencing disables the pixel FIFO, frontend enable and frontend
clock request, then waits up to 1 ms for both frontend clock-on witnesses to
clear. It rechecks packets and routing, clears the pixel input mode, and removes
only this frontend's bit from each connected backend. Unrelated frontend bits,
HPD selections, backend enables and clocks remain unchanged. HPO retirement
requires video, SDP and both FIFOs stopped, then disables SYM32 before its stream
clock request and waits up to 1 ms for all four clock-on witnesses to clear.
It leaves the independent stream/link mapping and link encoder untouched.

Success enters `DpEncoderRetired` and records
`DpEncoderRetired::{stream,detached_backends}` in `Status::dp_encoder_retired`.
Failure after writes or cancellation retains `Failed` or
`RetiringDpEncoder(stream)` and blocks reuse until independent reset. No result
proves PHY, sink, timing, VPG/APG/AFMT, HUBP or memory retirement. Global and pipe
clock owners now also reject enabled DIO frontends/pixel FIFOs and HPO SYM32
encoders, plus requested or acknowledged frontend/stream clocks; video blanking
alone cannot authorize clock changes. `unsafe ColdBoot::retire_display_dp_encoder`
and its platform wrapper retain the same lifetime and drained GC12/SDMA guards.

`unsafe ColdBoot::disable_display_dp_sst(port: usize).await` and its platform
wrapper disable an inherited direct external legacy DP SST link before frontend
retirement. The index selects this owner's validated `display_paths()` inventory;
no caller-supplied transmitter, AUX or HPD substitution is accepted. The matching
DMUB and timing owners must be ready and the GC12/SDMA interrupt proofs drained.
USB-C, ACPI PHY transition interlocks and PHY SSC workarounds are outside this
initial API: callers must establish that the selected direct port needs none.
Callers independently stop sink, audio/metadata, HDCP and FEC producers, exclude
CPU/firmware/FAMS and concurrent display/link/clock/power/reset writers, and retain
every allocation and translation. eDP, MST, HPO and HDMI shutdown are separate.

Live register preflight requires SST mode on both frontend and backend, one
valid frontend selected by the actual backend route, and agreement with the
board's HPD selector. Video, packet and metadata producers must be quiet, FEC
inactive and reset state settled. A live backend requires its frontend still
enabled. Independent HPO/FRL link consumers reject conservatively until their
physical muxes have owners; unrelated legacy outputs may remain active.

The private native DMUB operation sends VBIOS transmitter-control v1.7 DISABLE
(type 128, subtype 1, 60-byte payload). Physical transmitter and one-based HPD
come from the retained board path; frontend selection is zero as required by
the DCE112+ command helper, leaving routing to the driver. Native inbox
consumption alone is insufficient: the display owner waits up to 100 ms each
for backend enable and requested/acknowledged backend clocks to clear. It then
revalidates routing and frontend state, clears training-pattern/training-complete
and alternate-scrambler state, and rechecks all witnesses. It never directly
gates backend clocks to manufacture firmware completion. A fully disabled
backend needs no command or cleanup writes. Frontend/FIFO state and unrelated
backend routes remain unchanged for the subsequent `retire_display_dp_encoder`.

Success enters `DpSstDisabled`, recording `DpSstDisabled::{path,frontend,
command_sent}` in `Status::dp_sst_disabled`. This historical evidence covers
firmware disable and digital backend-off only; it proves neither analog PHY
power gating nor sink, timing, plane or memory retirement. Errors after starting
enter `Failed`; cancellation retains `DisablingDpSst(transmitter)`. Both block
display/clock reuse and raw mailbox/scanner access through the retained owner.
The mailbox independently quarantines incomplete transport. Global/pipe clock
guards also reject requested or acknowledged backend clocks even if the backend
enable bit is already clear. No outcome permits allocation reuse.

`unsafe ColdBoot::retire_display_hpo_link(port: usize).await` and its platform
wrapper retire one external DP HPO digital link before the separate firmware
PHY shutdown. The port selects the retained validated board inventory. Native
PHY mux, independent stream-to-link mapper and PHY-derived root clock fields
must agree; neither the connector index nor its OTG implies a link instance.
Shared PHY routes, training/test modes, eDP, incomplete resets, rate/allocation
updates and mismatched shadow/live allocation rows reject before writes.
Every mapped stream must have completed video, SDP, FIFO, SYM32 and stream-clock
retirement. Unrelated active streams remain untouched. Callers independently
retire sink/MST bookkeeping and audio/metadata/HDCP producers, exclude CPU,
firmware/FAMS and concurrent display/link/clock/power/reset writers, and retain
all allocations and translations. The same drained GC12/SDMA guards apply.

The owner clears all six native allocation rows and sends ACT when slots are
allocated, then requires empty live rows and no pending update within 20 ms.
The self-clearing ACT request is not a completion witness. Only after drain may
DPHY disable be requested; enable, reset, scheduler and pending-transaction
status must clear within 100 ms before link-clock disable. Requested and
acknowledged link clocks must then clear within 1 ms. Route and stream state
are rechecked across transitions. An already stopped, empty link receives no
writes. PHY muxes, stream mapping, PHY output and root clocks remain retained
for the subsequent firmware PHY shutdown. Global and pipe clock changes reject
enabled PHY-derived HPO root clocks and outstanding DPHY activity independently
of the digital link-clock enable bit.

Success enters `HpoLinkRetired`, recording `HpoLinkRetired::{path,link,streams,
removed_slots}` in `Status::hpo_link_retired`. This is historical digital-link
evidence only; it proves no PHY, sink, timing, plane or memory retirement.
Errors after beginning the operation enter `Failed`; cancellation retains
`RetiringHpoLink(link)`. Both block display/clock reuse and raw mailbox/scanner
access until independent reset. No outcome permits allocation reuse.

`unsafe ColdBoot::disable_display_hpo_dp(port, DpSignal::{Sst,Mst}).await` and
its platform wrapper complete the direct external HPO DP transmitter shutdown
after digital-link retirement. `DpSignal` is exported by
`amdgpu_dmub_navi48`; callers must supply the inherited link's actual signal,
retire sink/MST bookkeeping and audio/metadata/HDCP producers, exclude concurrent
CPU/firmware/FAMS/display/link/clock/power/reset writers, and retain all memory
and translations. The port must need no USB-C/ACPI PHY interlocks or PHY SSC
workarounds. eDP and HDMI remain separate. The matching DMUB, board inventory,
timing and DDC owners must be ready and kernel GC12/SDMA interrupt proofs drained.

Live checks require empty HPO timeslots, stopped digital link and mapped stream
encoders, consistent PHY/root routing, no other root using this PHY, a disabled
corresponding legacy backend and no pending PHY request/acknowledgement. The
historical retirement snapshot is not authority to skip these checks. The native
DMUB v1.7 HPO DISABLE packet uses the board PHY/HPD and explicit SST/MST mode.
It preserves the native caller's zero connector-object field and zero-initialized
HPO engine ID encoding; it never substitutes the selected link index into that
DISABLE field.

After mailbox consumption the owner waits up to 100 ms for all four RDPCS lanes
to report DISABLE set and CLK_RDY/DATA_EN/REQ/ACK clear, then up to 100 ms for all
lane-clock requests and the TX clock request/ON witness to clear. These are
conservative shutdown acceptance conditions, requiring silicon validation.
No software write targets PHY lane or TX-clock controls. With routing, digital
retirement and PHY witnesses rechecked, only the selected SYMCLK32_LE source and
enable nibble is cleared; other root routes and all PHY muxes remain unchanged.
Already disabled lanes/clocks skip firmware, and an already parked root receives
no write. Global and pipe clock guards independently reject native RDPCS lane,
handshake and transmit-clock activity even when digital link/root enables are off.

Success enters `HpoDpDisabled`, recording `HpoDpDisabled::{path,link,signal,
command_sent}` in `Status::hpo_dp_disabled`. This historical evidence covers
lane-disable, TX-clock and root-route readback only, not analog power gating,
sink power-down or allocation reuse. Failure after starting enters `Failed`;
cancellation retains `DisablingHpoDp(transmitter)`. Either blocks display/clock
reuse and raw mailbox/scanner access until independent reset; the mailbox also
retains its own incomplete-transport quarantine.

`unsafe ColdBoot::retire_display_hdmi_tmds_encoder(stream).await` and the
serialized platform wrapper retire one of four native TMDS HDMI frontends.
The caller independently handles sink AVMUTE/blanking quirks, SCDC reset,
external retimers and audio/metadata/HDCP teardown, excludes CPU/firmware/FAMS
and concurrent display/link/clock/power writers, and retains all memory and
translations. Live mode must be HDMI (3), with no frontend/FIFO reset, audio
clocks, metadata, immediate-packet transaction, DP video or pending/locked HDMI
buffer. Selected backend routes must be single-frontend TMDS, without reset,
dual-link or HPO muxing. Unrelated live outputs remain untouched.
The native sequence clears all 15 generic packet schedules and their line
fields, waits for every packet-enable buffer and HDMI/VUPDATE buffer to drain,
resets deep-color/scrambler/clock-rate attributes, and waits for that update.
It then disables the pixel FIFO, frontend enable and clock request, waits for
DISPCLK/SYMCLK/TMDS frontend clock-off, clears the input pixel mode and detaches
only this frontend's routes. Routes, metadata and packet activity are checked
again after asynchronous waits and at completion. Global/pipe clock guards
also reject outstanding TMDS frontend clock-on, even after its request clears.
Backend, PHY and timing clocks are preserved: a TMDS OTG may still consume the
PHY symclk. No DMUB transmitter-disable command or PHY power transition occurs.
Success records historical `HdmiTmdsRetired { stream, detached_backends }` in
`Otg::Status::hdmi_tmds_retired`; it proves neither link nor memory retirement.
Failure after starting enters `Failed`; cancellation retains
`RetiringHdmiTmds(stream)`. Both block owner/clock/mailbox reuse until an
independent reset. TMDS backend/PHY shutdown follows timing-clock retirement
through the operation below.

`unsafe ColdBoot::prepare_display_hdmi_link(port, HdmiLinkRequest { stream,
pipe })` and `Otg::prepare_hdmi_link` light one direct TMDS HDMI port for the
staged black timing of `pipe`, with that timing still stopped. Scope: RGB at
the blank's 8, 10 or 12 bpc, a pixel clock of at least 25 MHz and a TMDS
character clock (`HdmiLinkReady::character_khz`, Linux's `phy_pix_clk`: the
pixel clock ×5/4 or ×6/4, truncated in 100 Hz as `get_norm_pix_clk`) of at most
`TMDS_MAX_KHZ`, the TMDS divide-by-four pixel divider and the DP DTO off. Planning requires a reusable
owner, a `Signal::Tmds` blank on `pipe` bound to the retained clock, a stopped
backend with no frontend, dual link or reset, an idle frontend and FIFO, no
backend already routed to the stream, no DCCG frontend symclk route, and every
unrelated consumer, packet/metadata producer and HPO root idle; refusals write
nothing. The native order is Linux's: DMUB `SET_PIXEL_CLOCK` v1.7 (the
`dcn3_get_pix_clk_dividers`-scaled clock, COMBO PHY PLL of the transmitter,
UNIPHY object id, HDMI mode, CRTC `pipe`, XTALIN, deep-colour ratio 0/1/2) and
the matching PHYPLL `DCCG_DEEP_COLOR_CNTL`; `TMDS_CTL0`; link-encoder setup
(DIO mux, HPD select, backend mode 3, clock, enable); DMUB `DIGX_ENCODER_CONTROL`
`STREAM_SETUP` v1.5; HDMI stream attributes (RGB, generic-packet v1, keepout, no
extra NULL, no scrambling; for 10/12 bpc `HDMI_DEEP_COLOR_DEPTH` 1/2 with
`HDMI_DEEP_COLOR_ENABLE`; GC every frame with NULL packets; no ACP;
AVMUTE off) with the frontend's OTG and stereo sources; the AVI InfoFrame as
Linux's `enc3_update_hdmi_info_packet(0)` writes it (HDMI double buffering
off, VPG GSP memory woken if gated, conflict clear, nine data words, immediate
update, generic packet 0 sent every frame on line 2); then the BE←FE route,
frontend mode 3, clock and enable, stream mapper, one pixel per cycle and the
native FIFO reset (a RESET_DONE handshake only while the frontend symclk runs,
else a 10 us settle); finally DMUB transmitter `ENABLE` (HDMI mode, four lanes,
symclk in 10 kHz). Above `TMDS_SCRAMBLE_KHZ` (340 MHz) HDMI_CONTROL also sets the data scrambler
and the 1/4-rate clock channel (`HdmiLinkReady::scrambled`); the PHY PLL and
transmitter still take the full pixel rate. Linux's encoder switches at
`>= 340 MHz` while its SCDC write switches at `> 340 MHz`; both use `>` here so
source and sink never disagree. Success needs all four lanes ready, TX clocks
on, backend
SYMCLK on and frontend DISPCLK/SYMCLK on: `HdmiLinkReady(transmitter)`. Every
write first re-verifies the owned registers, routes and consumers. The AVI
frame carries Linux's fields for RGB (active format valid, both bars, underscan,
uniform scaling, same-as-picture aspect, ITC, `total + 1` bar ends) with VIC 0
and default quantization: narf matches no CTA mode, and CTA-861 makes a VIC-0
format full-range RGB, which is what is sent. No Audio InfoFrame or AFMT audio
clock is enabled and no DCCG frontend symclk route is programmed, as
`dcn401_enable_stream` does for TMDS.

`start_display_audio(port, true, AudioInfo, endpoint)` (`Otg::start_hdmi_audio`)
programs the display half of HDMI audio on running video or live scanout.
For TMDS, in Linux's order: the DCCG audio DTO0 (source = OTG, module = pixel
clock in 100 Hz, phase 24 MHz; DCN401 has no audio DTBCLK DTO), the stream's AFMT audio
clock, IEC 60958 channel status (channels 1..8, update request), audio delay,
automatic ACR with hardware CTS and Linux's N/CTS tables (the 36-bpc table at
12 bpc, the 24-bpc table otherwise, HDMI's "Other" N for unlisted clocks), the
endpoint→DIG source and channel enables (`speakers_to_channels`), then the
Azalia endpoint the codec reports as ELD (`dce_aud_az_configure`: speaker
allocation, HDMI connection, SUPPORTS_AI, per-format descriptors with LPCM
rates limited by `check_audio_bandwidth_hdmi`, AC-3 stream formats, HBR
capability, lipsync, vendor/product, Linux's default port ids, the monitor
name), the Audio InfoFrame on line 2 (built by hardware from the codec's
channel allocation), `az_enable` and unmuted samples. The endpoint is the
stream's acquired `StreamEncoders::audio`, independent of its pipe or HPO
encoder index; a sink without LPCM is `Unsupported`. `stop_display_audio(port, true)`
mutes, stops the AFMT clock and Audio InfoFrame and disables the endpoint; HDMI
video cannot stop while audio runs. Modeset builds `AudioInfo` as
amdgpu_dm does (`hdmi_audio_info`: SADs at CTA revision 3+, the first 3-byte
speaker block or FL/FR+FC, the 0xFC name, VSDB latencies), starts audio after
scanout when the sink declares any mode, and stops it first on stop or unplug.
The HD-Audio controller and codec that stream samples are separate.

The same HDMI audio entry points dispatch to native FRL when its video is owned.
FRL programs AFMT4 (no DIO AFMT clock or APG), IEC 60958 channel status, source
and channels, the lane-character-clock N/CTS table and automatic hardware ACR,
then the acquired Azalia HDMI endpoint and sample enable. Only LPCM is advertised;
HBR is disabled, and SD timings clamp to two channels. The video must already
reserve exactly the audio packets-per-line and borrow mode that its retained
LPCM capabilities require. Inherited samples/ACR or an occupied endpoint reject
before audio programming. `Status::frl_audio` retains the owner through partial
writes; failure quarantines the display. Startup completes in one poll after
publication and rechecks video/link/format, AFMT/ACR and the endpoint. Live video
and source-test checks also verify owned audio. Audio stops before scanout/video:
mute samples, stop ACR and disable the endpoint, preserving the video-owned
Audio InfoFrame and AFMT memory state. Failed shutdown retains ownership.

All display audio shares one wall DTO, recomputed on start/stop: the lowest
HDMI audio pipe wins, using DTO0 from the TMDS pixel clock or DTO1 from DPREFCLK
for FRL. With no HDMI audio, the lowest legacy/UHBR DP audio pipe uses DTO1; no audio
leaves the clock unchanged. DCN401 has no audio DTBCLK DTO. Endpoint allocation
excludes every retained TMDS, FRL, legacy DP and UHBR audio owner. Models cover all
six FRL rates, RGB/4:2:0 depths, bandwidth admission, partial writes, late drift,
shared DTO selection and teardown. Physical playback remains unverified.

Legacy DP SST LPCM can run beside DSC on the DIO stream encoder. Modeset keeps
the sink's audio capabilities for these streams and starts audio after scanout,
with the same audio-first stop/unplug/retrain ordering as uncompressed DP.
Startup and live audio verification require fresh PPS packet-size, GSP11
enable/line, VBID[6] line, AFMT clock and secondary-master readbacks from the
existing DSC video owner. A DSC request alone does not authorize sharing;
unexpected audio packet/sample enables still reject before writes.
Stopping audio disables its samples, packet enables and Azalia endpoint while
preserving the shared AFMT clock and secondary master for GSP11. PPS data and
scheduling remain the video owner's until video stops. This extends the
existing LPCM path; the endpoint also advertises the sink's compressed SADs
and HBR, as for SST DP without DSC.
Register/protocol models are not physical image or audible-output acceptance.

`start_display_audio(port, false, AudioInfo, endpoint)` / `Otg::start_dp_audio` also dispatch
on owned UHBR SST video or its matching scanout. `Status::uhbr_audio` retains
the APG/Azalia owner. The APG instance follows the HPO stream; its input mux
selects the acquired Azalia endpoint independently of HPO, OTG and PHY indices.
Startup programs stream ID 0,
pair-mode channel enables 0xff, APG memory power, a DP ELD (rate-filtered LPCM,
compressed SADs unfiltered, HBR from the 8-channel 192-kHz probe),
ASP/ATP/AIP and SDP master. APG reset assertion and deassertion each wait up to
10 us through the shared async wait primitive; `StartingUhbrAudio` blocks replay
and display switching if either wait is cancelled. Before APG enable, fresh
transport/format/blank-width and audio/endpoint checks must pass. Returned
failures retain the owner in `Failed`; no uncertain audio/link state is reused.

`uhbr_audio_info` filters the sink's valid LPCM SADs before selection and again
at the trained link before audio starts. Its blanking budget follows Linux
`check_audio_bandwidth_dp` in 31.32 fixed point, including SSC removal, SDP and
main-link overhead and the 1.1 margin. The minimum width is the value actually
programmed by the native stream owner, including pixel padding, rather than
`populate_audio_dp_link_info`'s differently scaled derived field. Mono uses the
stereo layout; 3..8 channels conservatively use the eight-channel layout.
No remaining rates means silent video without an audio endpoint. Retained regression
vectors cover this explicit input contract at all UHBR rates/lane counts and
8/10/12-bpc RGB depths; they do not validate audible output.

Compressed DP streams keep their LPCM as Linux does: build_audio_output hands
dsc_cfg (bits per pixel in 1/16, num_slices_h) to check_audio_bandwidth_dp,
which budgets the compressed bpp and subtracts four EOC symbols per slice
(in Linux's unsigned arithmetic). `uhbr_audio_info_with` and
`mst_audio_info_with` take the stream's `DscConfig`; selection keeps audio on
UHBR SST DSC and on 8b/10b and 128b/132b MST DSC streams, the UHBR budget
uses the minimum blank width the compressed payload programs
(`uhbr_dsc_payload`), and startup re-filters at the trained link. The APG
and DIO AFMT share the PPS's secondary data path: legacy MST audio start
expects the PPS's AFMT clock and master (and the VSC/HDR SDP enables) and
stop leaves them set, as SST does. Native Rust tests replay4536 retained
UHBR and1512 legacy MST DSC vectors with compressed bpp, slices and an
explicit blank width. These static fixtures do not establish physical playback
or conformance to current external source.

Live UHBR checks verify retained MSA/format/blank width and APG/packet/endpoint
state. Stop disables audio packets and APG, then the endpoint, before scanout
or video retirement. It preserves the running video's SDP master; video stops
that path later. Failed shutdown retains ownership. The shared wall DTO includes
UHBR, with HDMI priority and endpoint collision checks across all transports.

On legacy 8b/10b MST, `start_display_audio(port, false, AudioInfo)` dispatches
to `Otg::start_mst_audio` only after the manager owns exactly one completed
payload for the stream. Incomplete payload/resource transactions reject before
programming. Startup verifies the running RGB 8/10/12-bpc transport (or its
matching live scanout), completed source SAT/VC updates, slot count and VC rate
against the retained timing and trained link. SAT rows may move as siblings
leave, but duplicate, foreign or overallocated rows reject. Other rows must
belong to frontends on this same MST link. Audio never changes payloads.

`mst_audio_info` filters the remote sink's valid LPCM SADs during selection and
again at startup. It shares Linux's fixed-point blanking calculation with UHBR,
using legacy MST's 40-symbol layout, 16-symbol SDP overhead, four-lane AV mapping
and FEC-removed link budget. Mono uses stereo layout and 3..8 channels use the
eight-channel layout. No surviving rates means silent video. The per-stream
DIO AFMT, secondary audio packets and Azalia DP endpoint follow the SST sequence;
valid compressed SADs pass through unfiltered and HBR follows the same budget's
8-channel 192-kHz probe, as dce_aud_az_configure does. Shared DTO and endpoint allocation
include the other display transports.

`Status::dp_audio` and `Status::mst_audio_payload: Option<MstAudioPayload>` retain
both the audio owner and its source allocation witness (`slots`, packed VC `rate`)
before the first write. Startup has no suspended wait after this publication.
Partial startup/shutdown failures retain both records in `Failed`. Live scanout
verification includes the payload/audio witnesses. Stop verifies transport and
payload before muting samples, disabling packets/AFMT and the endpoint; only
then may scanout, video and payload retire. The MST activation checkpoint covers
completed scanout before audio starts. Models cover independent stream/pipe/PHY
indices, all RGB depths, malformed/stale payloads, failures, endpoint collisions,
shared DTO and two-stream link handover. 2268 bandwidth vectors (plus 1512
compressed ones) match Linux's routines. A compressed MST stream's payload
witness expects its compressed VC rate. Physical audio acceptance remains
outside this contract.

`start_display_hdmi_video(port)` starts the blank timing, repeats the FIFO reset
under live symclk, clears AVMUTE and waits for a fresh frame
(`HdmiVideoRunning(stream)`); scanout may start from it exactly as from DP video
and returns to it when stopped. `stop_display_hdmi_video` sets AVMUTE, holds
three frames (dcn30_set_avmute), stops the timing and restages the OPP route
(`HdmiLinkReady`). `stop_display_hdmi_link` sends DMUB `DISABLE`, observes the
backend, lanes and TX clocks off, then stops the FIFO, frontend and its clock,
detaches the route, stops generic packet 0 and restores the HDMI attribute
defaults: `HdmiLinkStopped`,
a reusable state. Failure enters `Failed`.

`unsafe ColdBoot::retire_display_hdmi_frl_encoder().await`, its serialized
platform wrapper and `Otg::retire_hdmi_frl_encoder` retire the single native
FRL frontend. The caller independently handles sink AVMUTE/SCDC/retimers and
audio/ACR/metadata/HDCP teardown, excludes CPU/firmware/FAMS and concurrent
display/packet/link/clock/power/reset writers, and retains all allocations and
translations. Live preflight requires settled FIFO/tribyte reset state, no
immediate packet or HDMI/VUPDATE transaction, quiet native DME4/metadata and
audio/ACR scheduling, and a valid OTG selector. Active FIFO/tribyte inputs must
match the enabled native HDMISTREAMCLK route. Enabled streams require all three
stream-clock acknowledgements; incomplete inherited clock transitions reject.

Native packet retirement clears both generic scheduling registers and all eight
line/EMP registers, then waits up to 150 ms for HDMI/VUPDATE buffers to drain.
Unlike TMDS, FRL's packet-14 line register contains no per-packet enable-pending
status. After fresh packet, routing and producer checks, the FIFO is disabled
before the tribyte encoder. Pending buffers must drain before disabling the
stream-clock request and waiting up to 1 ms for DISPCLK, SOCCLK and
HDMISTREAMCLK acknowledgements to clear. Completion rechecks packets, resets,
routes and producer state. A fully retired stream is a read-only no-op;
uncertain work on an already-disabled stream rejects without waking it.
General-control/AVMUTE configuration, pixel format, clock routing, timing,
link/PHY and independent AFMT/VPG owners remain untouched. The upstream FIFO
video-active indication is not interpreted as a downstream clock-off witness.

Success enters `HdmiFrlRetired` and records historical
`FrlEncoderRetired { pipe, was_active }` in `Status::frl_encoder_retired`.
The pipe is an OTG selector, never an inferred physical port. No result proves
link, PHY, sink, timing, AFMT/VPG, HUBP or memory retirement. Failure enters
`Failed`; cancellation retains `RetiringHdmiFrl`. Both block reuse until an
independent reset. Shared global/pipe clock guards and legacy DP shutdown now
also reject outstanding FRL stream-clock acknowledgements, FIFO/tribyte resets
and digital FRL link enable/reset or requested/acknowledged link clocks.

`unsafe ColdBoot::retire_display_frl_link(port).await`, its serialized platform
wrapper and `Otg::retire_frl_link` retire the board-routed native FRL digital
link. Callers fulfil the frontend retirement, sink/SCDC/retimer,
audio/metadata/HDCP and writer-exclusion obligations above and retain all memory
and translations. Live preflight requires a fully stopped frontend, a unique
PHY mux selecting HPO HDMI instance zero, a stopped selected legacy backend,
and matching character-root and forced PHYD18CLK routes. Enabled links require
clock-on; reset, calibration, reserved patterns, scrambler bypass and partial
inherited transitions reject before writes.

The native sequence selects zero training patterns, disables link enable,
gates its clock request, waits up to 1 ms for clock-off, then restores RC
compression. Fresh frontend, packet, routing and configuration checks precede
clock gating, compression cleanup and completion. A fully stopped native link
is a read-only no-op; incomplete shutdown never wakes or replays the encoder.
Success enters `FrlLinkRetired` and records historical
`FrlLinkRetired { path, lanes, was_enabled }` in `Status::frl_link_retired`.
It preserves PHY output, forced input clocks, character/stream roots, timing
and other outputs, and proves no PHY, sink or memory retirement. Failure enters
`Failed`; cancellation retains `RetiringFrlLink(transmitter)`, blocking reuse
until independent reset. Shared clock guards also reject an enabled FRL
character-clock root after digital-link retirement.

`unsafe ColdBoot::enable_display_dp_phy(port, DpPhySettings { lanes, rate }).await`,
its serialized platform wrapper and `Otg::enable_dp_phy` start one untrained
legacy 8b/10b DP SST PHY. The board path must be direct external DP, without
USB-C/ACPI interlocks or SSC workarounds. The caller validates board/sink/cable
limits and excludes sink/audio/metadata/HDCP/FEC producers, firmware/FAMS and
concurrent display/link/clock/power/reset writers. All allocations/translations
remain retained. Applied global clocks from the matching retained clock owner
are mandatory. Supported requests are 1/2/4 lanes at RBR/HBR/HBR2/HBR3.

Live preflight requires stopped outputs, detached selected frontend routing,
all selected PHY lanes disabled, no lane/TX clock activity, no PHY-fed clock
consumers and no pending training, test, FEC or panel state. Prepared stopped
timing may retain clocks only through acknowledged DPREF/DTB pixel DTOs. Native
setup selects legacy PHY muxing and board HPD, enables DP backend mode/clock/
backend, writes the lane count and advances the scrambler. Unrelated mux and
scrambler fields are preserved. Fresh controls and lane-off checks precede the
firmware command. The native DMUB v1.7 ENABLE packet uses board PHY/HPD, lane
count and symbol clock in 10 kHz units; its zero-initialized connector and HPO
fields follow Linux's DP enable caller, independently of the DISABLE packet.

Mailbox consumption is only transport completion. Bounded 100 ms waits require
exactly the requested number of physical lanes clock-ready without reset,
disable or REQ/ACK activity, with every unused lane disabled, matching lane/TX
clock requests and TX clock-on, and backend symclk-on. Physical lane reversal
is allowed; DATA_EN on used lanes is not a training witness. Fresh final
control/consumer/lane/clock checks precede `DpPhyReady(transmitter)` and historical
`Status::dp_phy_ready: Option<DpPhyReady>` containing path, settings and observed
physical lane mask. This state blocks general display/clock/raw-mailbox reuse.
It proves no sink power, link training, measured link rate, stream or scanout.

`unsafe ColdBoot::disable_display_dp_phy(port).await` and its platform wrapper
only stop this owner's matching still-untrained ready PHY. Fresh control and
lane/clock evidence precede native DMUB DISABLE; independent bounded waits
require backend, all lanes and TX clocks off before native training/panel
cleanup. Success enters reusable `DpPhyDisabled`, preserving the historical
ready record without granting analog power-gating or memory-reuse authority.
Failures enter `Failed`; cancellation retains `EnablingDpPhy`/`DisablingDpPhy`.
Incomplete transitions retain all owners and block replay until independent
recovery; unfinished firmware commands additionally quarantine the mailbox.

`unsafe ColdBoot::train_display_dp_link(port, downspread).await`, its serialized
platform wrapper and `Otg::train_dp_link` train only the matching retained
`DpPhyReady` legacy SST link at its current lane count and rate. The caller
fulfils the PHY operation's direct-port, writer-exclusion and memory-retention
obligations, excludes fixed-drive retimers, eDP, USB-C and MST/FEC work,
and supplies the actual board/firmware PHY downspread setting. This boolean
describes existing SSC; training does not reprogram its source. No automatic
rate/lane fallback, stream enable or scanout is implied.

Training enters `TrainingDp(transmitter)` before the first AUX transaction.
It requires DPCD 1.1 or later, requests sink D0, waits at least 1 ms and checks
power readback, then reads live base/extended capabilities on the board AUX
channel. Malformed/insufficient lane/rate/coding/framing capabilities, branches,
enabled MST or FEC-ready sinks reject, before any register write. DP
repeaters (LTTPRs) are handled as Linux's DCN401 (always VBIOS-LTTPR-aware):
the AUX engine's reply timeout is set to 3.2 ms (AUX_DPHY_RX_CONTROL1, as
dce_aux_configure_timeout) before the 10-byte capability block at 0xF0000 is
read. A NACK is absence and restores the 552-us default; timeout, protocol
failure and exhausted DEFER are errors. A repeater is present when its count
is a single bit and its lane count is 1..=4 (the revision is not checked).
Its maximum rate and lanes bound the link like the sink's. The owner echoes
TOTAL_LTTPR_CNT and sets transparent mode (0x55). When the VBIOS display caps
carry DCE_INFO_CAPS_LTTPR_SUPPORT_ENABLE (`inventory::lttpr_non_transparent`)
it switches to non-transparent mode (0xAA), reads each repeater's EQ
AUX_RD_INTERVAL, and trains each repeater before the sink, farthest first:
TPS1 CR at the sink's CR interval, TPS4 EQ at the repeater's own interval,
status and adjust requests from the repeater's 0xF0030/0xF0033 block, and
"training done" (0) written to its pattern register on success or failure,
the drive restarting at level 0 for the next hop. The CR interval follows
get_cr_training_aux_rd_interval: 100 us in non-transparent mode without a
DPCD interval, and an LTTPR implies the 16-ms interval for pre-1.2 sinks. The
port scan reads the same capability block (with the boot owner setting the
long timeout on DP ports beforehand and restoring the default where none
answered), and the modeset bounds its maximum link by it. Native AUX retries DEFER at most six times with 1 ms delays.
The owner sets and checks 8b/10b coding, enhanced framing, lane count, link rate
and sink downspread, without granting post-training adjustment requests.

TPS1 clock recovery and capability-selected TPS2/3/4 equalization program both
the source's native pattern/complete/bypass/PRBS registers and sink training
registers. HBR3 requires TPS4 support. Each first pattern update bursts the
pattern and all active lane settings together. Subsequent updates change only
lane settings. TPS1/2/3 disable sink scrambling; TPS4 retains it. Native DMUB
v1.7 drive commands use uniform maximum requested swing/pre-emphasis across
active lanes, clamp pre-emphasis to `3 - swing`, and follow the native caller's
zero signal/HPO encoding. DPCD maximum-level flags are separate from the VBIOS
drive byte. Fresh PHY lane-handshake and source/consumer checks surround drive
changes and AUX waits. Non-training AUX traffic is excluded during training.

Clock recovery stops after five unchanged swing requests, maximum swing, or
100 total attempts. Equalization allows six attempts and requires retained CR,
per-lane EQ/symbol lock and interlane alignment. Native base-DPCD training
intervals are honored asynchronously, including extended-capability indication
and interval encodings through 64 ms. Confirmed CR/EQ failure exits to native
idle when transport and source state remain trustworthy, then quarantines the
owner; uncertain I/O errors issue no speculative cleanup. Successful training
disables sink training, programs native source passthrough/idle framing and
scrambler BS count, and waits 5 ms before fresh sink configuration/power/status
and source/PHY checks. Post-LT adjustment-in-progress cannot complete training.

Success enters `DpLinkTrained(transmitter)` and records historical
`Status::dp_link_trained: Option<DpLinkTrained>` with PHY/settings, EQ pattern,
drive levels, downspread and CR/EQ attempt counts. It blocks general owner,
clock and raw-mailbox reuse; all frontends, video and scanout remain stopped.
`unsafe ColdBoot::stop_display_dp_link(port).await` and its platform wrapper
accept only this matching streamless trained state. SST sink D3 acknowledgement
precedes firmware PHY disable; idle MST roots retain D0 for notifications.
Independent backend/lane/TX-clock-off waits and
native training/panel cleanup. Success returns to reusable `DpPhyDisabled`,
preserving historical training records without releasing memory. Failure enters
`Failed`; cancellation retains `TrainingDp` or `StoppingDpLink`. Both retain
owners and block replay until independent recovery. These are software-model
proofs, with physical link operation still requiring silicon validation.

`unsafe ColdBoot::prepare_display_dp_frontend(port, DpFrontendRequest { stream,
pipe }).await`, its serialized platform wrapper and `Otg::prepare_dp_frontend`
prepare a native legacy SST frontend for the matching trained link and staged
full-range RGB OPP black pattern. Frontend, OTG and board PHY indices are
independent; none may be inferred from another. Callers fulfil the training
operation's topology, external-writer exclusion and resource-retention contract,
and retain exclusive timing/clock/OPP ownership. Timing and video remain stopped.

Preflight requires the matching `DpLinkTrained`, current applied clock owners,
live divider/reference readback, matching prepared DP timing/OPP depth and no
inherited packet/audio/metadata, format-buffer or reset work. Read-only retained
clock references may validate a live PHY; clock programming and ordinary idle
references keep their existing all-consumers-stopped checks. A payload ceiling
uses the actual trained lane count/rate and reduces 8b/10b capacity to 97% when
FEC runs. Uncompressed RGB uses its component depth; DSC uses the validated
PPS's bits per pixel and per-slice overhead, so a mode which needs compression
is not rejected against its uncompressed size. This native DSC path requires
8-bpc RGB and a FEC-trained link (SST or MST); other depths and insufficient
compressed capacity reject before frontend writes. This is not DML admission
or a watermark proof.
Native pixel packing selects 1/2/4/8 pixels per cycle from pixel rate and DPREF.

`PreparingDpFrontend(stream)` is set before the first AUX wait. Fresh sink
configuration, D0 and per-lane/alignment checks precede writes and completion.
Setup routes the frontend symbol clock to the actual PHY, selects OTG/stereo
sources, programs uncompressed 8/10/12-bpc RGB or 8-bpc RGB DSC and native MSA totals,
starts, sync widths/polarities and active sizes, and disables SDP splitting.
It connects only this frontend to the trained backend, enables the native
frontend, waits for DISPCLK/SYMCLK acknowledgement, programs the independent
contiguous stream mapper, sets pixel packing/read-start level and acknowledges
both resync FIFO reset transitions before FIFO enable. Source, routes, stopped
timing and unrelated consumers are rechecked around transitions. No steering
reset release, M/N generation, video enable, timing start or scanout occurs.

Success enters `DpFrontendReady(stream)` and records historical
`Status::dp_frontend_ready: Option<DpFrontendReady>` containing the request,
trained-link snapshot, staged blank timing/depth and pixel packing. This state
blocks trained-link shutdown and all general owner reuse.
`unsafe ColdBoot::stop_display_dp_frontend(port).await` and its wrapper accept
only the matching blank frontend. Native FIFO/frontend/clock disable precedes
independent clock-off acknowledgement, backend detachment and symbol-clock
route parking. Fresh restored streamless-link evidence returns the owner to
`DpLinkTrained`, permitting its existing sink-D3/PHY shutdown. Historical
frontend records remain, without granting memory reuse. Failure enters `Failed`;
cancellation retains `PreparingDpFrontend` or `StoppingDpFrontend`. Both prevent
replay and retain resources until independent recovery.

`unsafe ColdBoot::start_display_dp_video(port).await`, its serialized platform
wrapper and `Otg::start_dp_video` start native legacy SST RGB black video from
the matching `DpFrontendReady`. Callers retain the direct-port, exclusive
clock/timing/OPP/PHY ownership and external-writer exclusion obligations for
the entire running lifetime. All surfaces, translations and inherited resources
remain retained. This operation enables no memory fetcher, audio, metadata,
DSC, MST, UHBR or surface scanout.

Preflight checks current retained clocks, unchanged frontend/link/OPP state,
stopped HUBPs/cursors/metadata/LUT fetchers and settled power-gating witnesses.
Powered-off HUBPs remain inaccessible. Non-default M/N dividers or
double-buffer programming reject before writes. The prepared, stopped
frontend owns any retained measurement generator and disables it before
reseeding. `StartingDpVideo(stream)` is
set before the first AUX wait; live sink configuration, D0 and per-lane/alignment
checks precede timing startup. Native VTG-before-OTG enable must acknowledge
master enable, latched OPP/FMT black and fresh frame progress before video setup.
All unrelated display consumers remain stopped and checked.

Native M/N programming seeds N=32768 and M=floor(N*pixel_kHz/link_symbol_kHz),
sets N interval for the retained 1/2/4/8-pixel packing and enables automatic
measurement. M is a seed, not a fixed live completion witness. Video-off
acknowledgement precedes steering reset; both reset directions acknowledge and
the native 10 us reset hold is preserved. Steering enable, video enable/defer=2,
200 us priming, read-start level=7, both resync FIFO reset acknowledgements,
FIFO enable and 100 us priming precede the final video-enable request. Fresh
video status, sink revalidation and subsequent frame progress are required.
Timing/video/frame waits use three mode-derived frame periods plus 5 ms,
bounded at 1 s; steering and resync reset waits are bounded at 1 ms and 50 ms.
All waits yield through the existing scheduler/time/transport primitives.

Success enters `DpVideoRunning(stream)` and records historical
`Status::dp_video_running: Option<DpVideoRunning>` with frontend/link/blank
identity, initial M/N and two distinct post-enable frame counters (wrap allowed).
The source and sink witnesses do not prove that the physical display presents
black. This state blocks ordinary timing retirement, clock programming,
frontend/link teardown and replay.

`unsafe ColdBoot::stop_display_dp_video(port).await`, its wrapper and
`Otg::stop_dp_video` accept only that matching live owner. Video disables at
vertical blank and must acknowledge off while timing/clocks remain available.
Only then may steering reset/disable and M/N generation stop. Native timing
shutdown disconnects ODM, clears memory selection and disables master/VTG,
requiring both master-off and busy-off acknowledgements. Fresh stopped source,
timing, blank and fetcher checks precede restaging the single OPP route with
timing still disabled. Success updates the prepared frontend snapshot and
returns to `DpFrontendReady`, permitting black-video restart or existing
frontend/link shutdown. No memory or PHY is released. Failure enters `Failed`;
cancellation retains `StartingDpVideo` or `StoppingDpVideo`. Both quarantine the
owner, retain completion history and block replay until independent recovery.
Physical video operation and native surface scanout remain separate work.

`unsafe ColdBoot::disable_display_frl(port).await`, its serialized platform
wrapper and `Otg::disable_frl` disable a validated direct external HDMI FRL PHY
after frontend and digital-link retirement. The caller fulfils the same sink,
SCDC/retimer, audio/metadata/HDCP and writer-exclusion obligations, without ACPI
PHY interlocks or SSC workarounds, and retains all allocations/translations.
Live checks require the complete native digital-off state, unique board mux,
quiet selected legacy backend, no PHY handshake and matching retained root
routes. Shared HPO link roots, inherited enabled HPO stream roots and frontend
symclk consumers of this PHY reject before commands. Live timing must use an
acknowledged DPREFCLK/DTBCLK DTO, without pixel add/drop, reset or buffered timing
transactions; PHY-fed TMDS timing rejects. Consumer routes and configuration
are checked again across firmware/hardware waits and root parking.

The native DMUB v1.7 DISABLE packet uses FRL mode 4, HDMI connector ID, board
PHY/HPD and the zero-initialized caller's HPO encoding. Mailbox consumption
only completes transport. Independent waits of up to 100 ms each require all
four RDPCS lanes disabled with CLK_RDY/DATA_EN/REQ/ACK clear, then all lane/TX
clock requests and TX clock-on clear. Only then is the character-clock root's
enable/source cleared. The host never writes firmware-owned lane/TX witnesses.
Inherited fully stopped PHYs skip the command; retained root parking still
requires fresh consumer checks. Native forced PHY input clocks remain retained,
as do DTOs, timing and unrelated outputs. This proves no analog power gating,
sink, memory or translation retirement.

Success enters `FrlDisabled` and records historical
`FrlDisabled { path, command_sent }` in `Status::frl_disabled`. Failure enters
`Failed`; cancellation retains `DisablingFrl(transmitter)`. Both prevent owner,
clock and mailbox reuse until independent reset; unfinished firmware transport
also retains its own mailbox quarantine.

`unsafe ColdBoot::retire_display_tmds_timing(pipe).await` and its serialized
platform wrapper break the TMDS timing/PHY-clock shutdown dependency. Unlike
general timing retirement, this operation allows live TMDS backends and PHYs;
all frontends, FIFO/stream clocks, HPO/FRL links, audio and metadata must already
be stopped, and every backend frontend route detached. Live retained outputs
must have HDMI backend mode and legacy PHY muxing, without pending PHY
handshakes or backend resets. The operation snapshots backend routing, enable,
clocks, PHY muxes and lane/clock state across all four transmitters.
It disconnects the selected ODM inputs, stops OTG/VTG, waits for current-master
and busy acknowledgements, clears latched input underflow through the native
W1C command, then gates OTG followed by input clocks and waits for both to stop.
Retained link state and producer quiescence are rechecked before clock gating
and after completion. Other timing generators and all backend/PHY clocks remain
untouched. Pending master/input updates and resets reject before writes.
Success records `TmdsTimingRetired { pipe, retained_transmitters }` in
`Otg::Status::tmds_timing_retired`; it retires only that timing/clock consumer,
never HUBP fetches, PHYs or memory. Failure enters `Failed`; cancellation retains
`RetiringTmdsTiming(pipe)`. Both prohibit reuse until independent reset. Callers
must retain all allocations/translations and exclude CPU/firmware/FAMS and
concurrent display/link/clock/power writers. Future PHY shutdown must check all
live timing and clock users independently of this historical result.

`unsafe ColdBoot::disable_display_tmds(port).await` and its serialized platform
wrapper disable a validated direct external HDMI Type-A transmitter through
native DMUB v1.7 DISABLE. The caller must fulfil the same sink AVMUTE/SCDC,
retimer, audio/metadata/HDCP and writer-exclusion obligations, without ACPI PHY
interlocks or SSC workarounds, and retain every allocation and translation.
Live preflight requires all timing generators, OTG/input clocks and frontend
producers stopped, all backend frontend routes detached, no HPO/FRL activity,
no forced PHY input clock, stable TMDS retained outputs and a matching board
HPD selector. No historical retirement snapshot substitutes for these checks.
The selected enabled backend must have HDMI mode and a clock request. An
already-disabled backend is accepted only with clocks off and all lanes
disabled without data/clock/handshake activity; partial inherited shutdown
rejects without replaying the native command.

Only frontend symclk routes selecting this PHY are parked, clearing FE enable
and source while preserving unrelated clock bits and routes. Fresh consumer
and route checks precede firmware submission. The HDMI command carries native
HDMI mode, connector ID and the zero-initialized caller's HPO engine encoding.
After mailbox consumption, four separate waits of up to 100 ms require backend
disable, backend clock/reset-off, all four RDPCS lanes disabled with
CLK_RDY/DATA_EN/REQ/ACK clear, and all lane/TX clock requests and TX clock-on
clear. The host never writes these firmware-owned completion witnesses.
Completion rechecks consumers, routes, other outputs and the selected hardware
acknowledgements. Success records historical
`TmdsDisabled { path, parked_frontends, command_sent }` in
`Otg::Status::tmds_disabled`; this proves neither analog power gating nor memory
retirement. Failure enters `Failed`; cancellation retains
`DisablingTmds(transmitter)`. Both quarantine ownership until independent reset.

`amdgpu_navi48_boot::Firmware::open` prepares both mandatory firmware sets
before cold boot. `unsafe ColdBoot::new` requires exclusive GPU ownership,
the inventoried pool, trained VRAM or an owned training exchange, and all
training quiescence obligations. `run().await` retains the trainer, SOS,
PSP/TMR and SMU owners and executes training → SOS → ring/TMR → SMC → SMU
version/board transfer → DMUB stop → graphics autoload → RLC readiness →
RS64 program counters → initial power policy → harvested GC12 topology.
DCN4 stop requires STOP_FW acknowledgement and PWAIT,
uses CNTL2 reset, verifies disabled/reset readback and leaves PSP's secure
windows untouched. Every stage is observable through `State`; failure or
cancellation prevents replay. The sequence then initializes GMC12 and SDMA7,
configures GC12/RLC and unhalts RS64, starts unified MES12's firmware queues,
and starts DMUB with a validated
version/capability handshake. `MemoryReady` reports firmware/media/power status,
the VMID0 aperture, verified DMA proof and MES queue report. User queues,
native display and physical validation remain separate gates;
`fw_loaded` is not set by this API.

`amdgpu_gfx12_rs64::Rs64` prepares immutable PFP/ME/MEC entry points from the
exact GC12 firmware set. After PSP authentication and RLC autoload, its one-shot
`unsafe configure` programs two PFP/ME and four MEC counter banks using dword
addresses and pulses only the corresponding pipe-reset bits. It first refuses
busy CP/MES or inherited graphics/compute queues, preserves unrelated controls
and restores the GRBM selector on errors as well as success. A single live
capability invocation covers the finite indexed sequence, with write readback.
Failure prevents replay. `Report::rs64` records completed configuration; this
does not activate queues, unhalt command processors or prove graphics execution.

`unsafe amdgpu_gfx12_setup::Setup::new` reserves an owned RLC clear-state page.
After RS64, restricted power, GMC and the SDMA proof, `unsafe initialize().await`
requires inactive CP/MES queues and applies GC12 golden settings. It reads the
ASIC strap using the NBIO7.7 or NBIF6.3.1 offset; revision-zero workarounds do
not affect later revisions. Shader-engine broadcast and queue/VMID selectors
are restored on every exit. Constants configure shader access for every
graphics VMID (0–7: DEFAULT_SH_MEM_CONFIG; 1–7 also SH_MEM_BASES with
gmc_v12_0's private/shared apertures), the single graphics pipe, eight
hardware contexts and disabled GUI-idle IRQs.
Publication
retains the page through cancellation/failure; the driver programs CSIB and
enables RLC save/restore before activating four MEC stacks and unhalting PFP/ME.
An async bounded idle wait must succeed before `Report::setup` becomes valid.
This stage makes command processors available but publishes no application queue.

`amdgpu_mes12` serializes MES12's 64-dword frames using its eight-byte C
alignment, separately from MES11's four-byte alignment. It provides bounded
SET_HW_RSRC/SET_HW_RSRC_1, query-status and native kernel queue map/unmap
commands, typed completion binding and API-error decoding only after the
trailing query fence drains. A drained rejection advances the command sequence
just like a success, preventing reuse of its trailing completion fence.
`detect_hung_queues(QueueType, output)` emits RESET's detect-only variant;
`hung_queues` decodes four doorbells and four corresponding packed HQD IDs,
preserving holes and rejecting duplicate, reserved, misaligned or invalid IDs. Native MQDs use `v12_compute_mqd`, including
`DB_UPDATED_MSG_EN`, privileged VMID0 and the MES-owned read pointer. Descriptor,
ring, EOP and pointer ranges must be aligned, disjoint and within 48 bits;
resources never delegate VMID0 to the scheduler.

`unsafe amdgpu_mes12_hw::Mes::new` requires exact RDNA4 GC12.0.0/12.0.1, MMHUB4.1,
OSSSYS7 and NBIO7.7/NBIF6.3.1 discovery, matching **unified** MES firmware,
exclusive GRBM/queue ownership and a permanently mapped, uncached BAR2.
It reserves 40 KiB of inventoried VRAM for two rings, native descriptors, EOPs,
pointer/fence slots and separate cleaner-fence pages. `unsafe start().await`
requires successful PSP/RLC/RS64/GMC setup and the translated DMA proof. It
refuses inherited MES execution, enables the PCIe aperture, programs soc24
doorbell ranges and RLC's KIQ selection, starts both firmware pipes, and
initializes KIQ pipe 1 through MMIO. Live versions must support kernel queue
mapping and memory write pointers. Separate MES1 PM4 firmware is never sent
MES API frames.

The owner sends KIQ resource commands, maps scheduler pipe 0 through KIQ,
configures scheduler resources and aggregated doorbells, then queries its
status. Every submission is a native frame followed by a query frame; success
requires the API result, exact query sequence and full read-pointer drain.
Owned ring slots wrap without exposing caller-supplied addresses. All device
access batches invoke current PCI authority; finite indexed batches restore
GRBM before awaiting. Version/command waits have 2.1-second deadlines using
scheduler timers. Publication quarantines every firmware-visible allocation
through cancellation or failure and prevents replay. `State`/`Report` expose
firmware progress, live versions and completed commands, **not** application
acceleration. No application queue or user VMID is delegated yet. The private
bootstrap mapping path maps the two owned graphics/compute HQDs through
**scheduler pipe 0**, following MES12's distinct routing for ordinary kernel
queues. A mapping failure/cancellation stops further MES commands.

`unsafe amdgpu_gfx12_queue::Queues::new` reserves 24 KiB for native graphics
and compute MQDs, two 4-KiB command rings, EOP storage and pointer writebacks.
It requires ownership of gfx/compute pipe 0 queue 0 and doorbells 0x116/6;
the completed MES owner supplies the same uncached BAR2 mapping. `unsafe
initialize(mes, gmc).await` requires successful RS64/RLC setup and the matching
GMC/MES owners. It rejects active inherited HQDs, validates the owned two-page
VMID0 test aperture, flushes descriptors and commands, then publishes storage
before asking MES to map either queue. Graphics and compute use their native
MQD fields: the compute ring enables hardware RPTR writeback and its own
quantum, rather than inheriting the MES firmware's pointer policy.

Each queue submits a 256-dword-aligned, driver-generated WRITE_DATA sequence
to one translated test page, followed by a confirmed fence and bounded NOP
padding. `Proof` requires the fresh engine-specific fence, the full **32-bit**
GC12 read-pointer drain and every expected data word. No caller command or
address is accepted. The 2.1-second wait uses scheduler timers and current
capability checks; cancellation or any failure retains mapped storage and
prevents replay. The cold-boot coordinator retains these queues and both GMC
pages, recording the proof before DMUB startup. This proves kernel command
transport and translated writes, not rendering, shader dispatch or user IBs.

After IH service handoff, `unsafe Queues::prove_interrupts(gmc).await` submits
one native RELEASE_MEM EOP per retained kernel queue. It verifies that the
interrupt service enabled the native timestamp/generic sources, then advances
each ring from 256 to 512 dwords. Success requires
the fresh confirmed fence, full RPTR drain and exactly one matching IH EOP
since the pre-submission snapshot. With MSI configured, both submissions must
also advance the CPU vector's fire count; polling alone returns an
`InterruptProof` with `msi_verified=false`. Existing/new VM faults, changed
routing, duplicate EOPs, revoked authority, malformed apertures or a 2.1-second
timeout cannot report success. No command accepts user addresses or data.
Cancellation retains the `InterruptSubmitted` state, sources and all backing;
failure retains `Failed` and its error, and neither permits replay. Success
records `InterruptVerified`. `interrupt_result` and the original write proof
remain separate, so the latter cannot imply interrupt delivery.

`unsafe Queues::prove_shaders(gmc).await` optionally follows both GC12 and
SDMA interrupt proofs, before any client work. It requires both GC12 rings
drained at 512 dwords and exclusive ownership of the two GMC test pages and
every queue using them. It promotes only the owned source page's VMID0 PTE
to executable, flushes HDP and waits for the GFXhub TLB acknowledgement;
the destination and all unowned PTEs keep their permissions. Cancellation
during this preparation retains GMC `PreparingShader`, which is not ready
for VMID0 use; a returned error retains `Failed`.

The generated IB programs GC12 logical SH resource registers and dispatches
one wave32 threadgroup, first on graphics and then on compute, under VMID0.
The fixed gfx1200/gfx1201 shader stores a queue-specific salt XOR each lane's byte
offset to 32 output words. Code and IB occupy the first owned page; output
and poison guards occupy the second. There are no caller-supplied shader
bytes, resource addresses, LDS or scratch. Each submission invalidates shader
caches and uses the real job fence sequence. Success requires all lane values,
every guard word in the output page, the exact fresh fence, full RPTR drain
and a fresh matching EOP (plus CPU delivery for configured MSI), within
2.1 seconds. The two sequences continue into subsequent client jobs.
`amdgpu_gfx12_shader::Proof` and `shader_result()` retain this evidence
separately from command-transport and interrupt proofs. Once preparation starts,
cancellation retains `ShaderSubmitted(pipe)`; failure retains `Failed(error)`.
Both block further submissions and proof replay and quarantine backing. Successful proof returns
to `InterruptVerified` and cannot be repeated.

The platform schedules this second proof as an executor task after boot,
because framebuffer initialization may run with CPU IRQs masked. The proof
refuses MSI submission if IRQs are still masked. Diagnostics expose
`queue_state` and `queue_interrupts` separately from the historical cold-boot
report; while their owner lock is held, platform status is `Running`.
The boot flag `amdgpu.shader_proof` opts into shader proof after SDMA's
interrupt proof, while the same owner lock excludes clients and clear work.
Diagnostics expose `shaders` separately; failure prevents the subsequent
clearer publication. Explicit whole-device recovery repeats the requested
shader proof on fresh owners before publishing its new submitter. This
diagnostic does not enable Mesa acceleration or prove draw/render state.

The same opt-in then schedules `amdgpu_navi48_client_shader` through the
registered native submitter, after releasing OWNER. Two owned per-open GEM
and context tables allocate distinct 8 KiB GTT BOs, GMC12 page-table roots
and PASIDs; both roots map the same virtual address. Typed internal
`GemState::create_kernel_system` and `VmInner::map_kernel_object` borrow
that card's placement admission and never pass kernel pointers through user
copy-in. The diagnostic keeps runtime-PM access and placement admission
through all four jobs, acquiring OWNER only inside normal submission.
The entire client proof has a ten-second deadline, including queue admission.
Each root runs one fixed wave32 dispatch on graphics and compute, with
queue/client salts, native VMID/PASID grants, context-switch handling, HDP
request/ack and requested memory synchronization. Success requires a fresh
non-error job fence, matching EOP/CPU delivery and every code, IB, output
and guard word in both BOs, including the inactive peer. Diagnostics expose
`client_shaders` separately from the VMID0 proof. The async retained owner
keeps BO placements, tables, PASIDs and context health across cancellation
or failure; only a newly registered hardware generation after proved
quiescence/reset may replace this storage. Requested proofs repeat on
fresh submitters. Models exercise both RDNA4 dies, incorrect output,
cross-root writes, overruns, incomplete/error fences and missing interrupts;
they establish software ownership/readback contracts, not physical shader
execution. Mesa version/acceleration and codec advertisement remain gated.

That opt-in also schedules `amdgpu_navi48_client_draw` after OWNER is released.
It runs a genuine GFX12 META graphics rectangle on gfx1200/gfx1201, using
pinned Mesa26.2.4 ACO NGG/PS binaries and the unchanged graphics-preamble,
GE-ring, CB/descriptor, draw and cache-barrier constructors. The
pristine DRM shim records gfx1201; gfx1200/1201 family, physical SE count,
address32 and PFP version are explicit compiler/constructor inputs, not
physical board evidence. PFP's retained authenticated image selects the
pre/post-2680 constructor variant; discovered physical SE count must match.
That version comes from the retained container's common header, corresponding
to the loaded PFP payload; PSP does not independently attest that header field.

Each of two distinct per-open roots/PASIDs maps the same VA: code/IB are
readable/executable without write permission, while descriptors, upload,
target and GE working storage are readable/writable without execution.
GE sizing follows the primary max-SE-squared contract: 4 MiB for Navi44,
10.5 MiB for Navi48. The two complete arenas consume 12.125/25.125 MiB of
system/GTT backing respectively, plus page tables, and consume no driver
VRAM-pool reservation. Success requires fresh increasing native graphics
job fences, full RPTR drain, a fresh EOP/CPU-vector observation and exact
readback of 667 red pixels in `(7,11,29,23)`, 3429 untouched pixels and all
code/descriptor/padding/guard words in both clients. The allocated GE
interiors are unspecified working data and are excluded from post-readback;
their boundaries remain checked. The primary path does not require them
zeroed. Actual CB-to-host synchronization and BOTTOM_OF_PIPE PWS completion
precede the outer native job fence.

`Diagnostics::client_draw` reports this separately from compute proofs. The
ten-second operation retains runtime-PM access, placement admission and its
async backing owner across submission/wait/readback. Error or cancellation
quarantines storage; a matching new submitter can replace it only after
whole-device reset and fresh queue/IH proofs. Models exercise both targets,
VM permissions, wrong-root/pixel/guard errors, busy admission, incomplete or
failed fences, absent interrupts and canceled submissions. These establish
software lifetime/readback behavior; physical draw/cadence acceptance and
Mesa/DRM capability advertisement remain separate gates.

The read-only `amdgpu_dcn_inventory` routing functions support Navi48 with
GC12.0.0/12.0.1 and DCN4.0.1 (including raw discovery 4.1.0). ATOM display-object
tables v1.4/v1.5 supply independently resolved transmitter, AUX and HPD
identities; v1.5's reserved USB-C word is not treated as an external encoder.
DCN4 exposes four native AUX/transmitter/frontend instances and no DPIA route
through this interface. `transmitter_busy` reads DCN4's `0x20bd + n*0x124`
registers. Ambiguous wiring and unsupported channels are refused; these
inventory functions do not enable any DCN3 timing/plane/link programming.
DCE-info v4.5 supplies the unchanged reference-clock field. The DCN4 DMUB
mailbox likewise refuses native AUX/HPD channel indices outside `0..4`.

`amdgpu_navi48_display::Probe` retains board routing and the native DP/eDP/HDMI
scan transaction. `scan(&mut Dmub, Option<&mut Ddc>)` reads DP DPCD, uses advertised extended receiver
caps at `0x2200` when at least as new, then reads complete E-EDID with segment
pointer writes, 16-byte transfers and STOP at each block. It validates the
base header and every checksum, bounds EDID at 32 blocks and DEFER at seven
attempts with scheduler delays, and terminates I2C MOT after recoverable sink
errors. `Port` preserves independent board identities and per-port errors;
a NACK is not reported as an HPD disconnect. Fatal transport errors stop the
scan. Cancellation leaves `State::Scanning` and forbids reuse until reset.
HDMI paths use the native DDC owner; `Sink::dpcd` is `Some` for DP/eDP and
`None` for HDMI. A physical channel, transmitter or HPD identifier is never
substituted for another. Both DP and HDMI routes participate in ambiguity checks.

`unsafe amdgpu_ddc_navi48::Ddc::new(gpu, authority, crystal_khz)` prepares a
retained owner of DCN4's shared native-I2C arbitrator/buffer and all four DDC
pin pairs. Exact GC12.0.0/12.0.1 and DCN4.0.1/raw-4.1.0 banks are required; the
crystal comes from ATOM DCE-info. Preparation performs no device writes.
`edid(channel).await` refuses inherited SW/DMCU ownership, active hardware
transactions and autonomous EDID polling before writing. It wakes I2C SRAM,
enables the selected channel clock, acquires SW arbitration and configures
100 kHz from the live microsecond/XTAL divider. It saves selected GPIO,
pad-mux, speed/setup and control fields before altering them. Segment writes
and 128-byte offset-write/repeated-START/read transactions use the hardware
FIFO, not AUX. Fresh status reset, SW ownership, idle and DONE are required;
zero status alone never completes a transfer. Reads validate all EDID blocks
with the same 32-block limit. Segment-zero NACK is tolerated for older sinks.
Every hardware wait uses scheduler timers and a 50 ms bound.

Known-terminal NACK and EDID validation errors restore selected pin/config
fields and release arbitration, including the DCN4 second-DONE workaround.
SRAM and the selected channel clock remain awake. Timeout, unexpected status,
revocation and cancellation retain the claim/state and forbid replay until
independent reset. All MMIO batches invoke the PCI capability. There is no
Drop-time MMIO, bit-banging fallback, forced takeover or hardware reset.

`ColdBoot` keeps this scanner and any routing-preparation error independently
of engine startup. `display_paths` and `display_state` expose its inventory
and diagnostics; `scan_display` requires completed firmware/DMUB startup.
`amdgpu_navi48_platform` serializes these operations through the retained owner.
DDC preparation errors are independent of non-display startup. Raw DMUB access
is refused while a scan/DDC transaction is incomplete or failed, including
after cancellation, so AUX cannot reuse pins owned by a partial HDMI read.
This discovery API does not train a link or program a scanout mode.

`unsafe amdgpu_gmc_navi48::Gmc::new` validates GC12.0.0/12.0.1/MMHUB4.1/NBIO banks
and the pool's BAR0/GPU mapping. `initialize().await` requires retained
firmware and trained VRAM with both hubs idle. It creates a flat VMID0 table
mapping only two owned VRAM pages in a 2 MiB aperture above physical VRAM.
Page-table and fault-default backing also lives in the owned pool; no host
DMA or user VMIDs are enabled. Both hubs must agree on framebuffer geometry.
Programming uses the GC12 fault-response fields, disables fault interrupts,
invalidates engine 17 in both hubs and the MMHUB private cache, and retains
published backing across errors/cancellation. `Ready` follows both bounded
acknowledgements, not merely table publication.

`unsafe prepare_client_contexts().await` (after `initialize`) enables client
VMIDs 1..15 on both hubs as gfxhub_v12_0/mmhub_v4_1_0_setup_vmid_config does:
GMC 12 depth and block size in GC 12's CONTEXT_CNTL layout, every fault
default, no retry, bounds 0..max_pfn-1. Each context's base points at an
owned root page whose entries are GMC 12's invalid directory pattern, so a
VMID no submission has flushed faults instead of translating. One request
invalidates all fifteen per hub on engine 17, the MMHUB semaphore held and
released even on timeout; every context is read back. `ClientsReady` keeps
VMID0 live (`State::vmid0_ready`); failure quarantines the owner. The cold
boot's memory-translation stage runs it right after `initialize`, before any
queue exists.

After boot, the platform calls `ColdBoot::publish_client_vram`: the
CPU-visible VRAM the driver's pool still has free, less an explicit future-owner
reserve of max(32MiB, one eighth of the aperture capped512MiB), bounded by
current availability, 2 MiB-aligned, halved until one free run holds it, at least
64 MiB, becomes a separate pool, registered as the Navi48 DRM card's
`VramHeap` with the GMC's framebuffer geometry. The slice never returns to
the driver's pool, so clients without eviction cannot starve its owners.

The VRAM past a BAR that shows only a prefix of it is clients' whole:
`prepare` takes `Plan::unmapped_pool` beside `into_pool` (every driver owner
allocates from the CPU-visible pool) and hands it to `ColdBoot::new`. Once
SDMA0's interrupt proof passes, the platform calls
`ColdBoot::publish_unmapped_vram(clear)`, re-registering the clients' heap
with it as the `UnmappedHeap`. Its `VramClear` queues clears in order; one
drain task at a time submits the front ones (at most 32 fill packets) as a
kernel job (`ColdBoot::submit_client_sdma_kernel`) under the platform owner,
retrying while the ring is full, so clears run and complete in queue
order. A clear's fence is its job's SDMA ticket, judged by the card's
submitter; a device that refuses the job for good (or has no owner)
signals it, as nothing can run there any more.

`unsafe amdgpu_ih7::Rings::new` prepares native OSSSYS7.0.0 rings with exact
GC12/NBIO discovery banks. It rejects inherited enabled rings, enabled host
delivery or non-idle IH before allocating; preparation never writes hardware.
`initialize(&Gmc)` requires the same GPU's ready VMID0/MMHUB and exclusive
firmware/reset/source ownership. It publishes retained 256 KiB main and
16 KiB secondary rings plus a writeback page in owned VRAM, using VMID0 GPU
addresses rather than host physical DMA. It configures the native register
order, redirects GC retry vectors to ring1, restores the indexed selector,
and enables both rings with **host interrupt delivery disabled**.

`drain()` returns an allocation-free `Batch` with at most sixteen `Event`s
from each ring. `Vector` decodes the native 32-byte IV: client/source/ring/VMID
and VMID source in dword0, 48-bit timestamp and its source in dwords1–2,
PASID/node in dword3 and four source payload dwords. SOC21 GC client is `0x0a`.
Pointers are byte offsets; partial vectors, out-of-range/undefined bits and
unexpected read pointers are errors. The consumer checks overflow both before
and after copying, flushes HDP visibility, and acknowledges only complete
vectors. `Batch::pending` requires another bounded drain after yielding.
A ring0 overflow (the only ring with WPTR_OVERFLOW_ENABLE) is recovered as
ih_v7_0_get_wptr does: reading resumes at WPTR + 32, the oldest vector not
overwritten, and WPTR_OVERFLOW_CLEAR is pulsed (set, then cleared with
readback) so the next overflow is seen. An overflow that races the copy
discards the whole batch, leaving ring1 unread, and recovers the same way.
Either case sets `Batch::lost` and counts `overflows()`. Still overflowing
right after the clear, four consecutive overflowed drains, or any ring1
overflow (ring1 drains full instead) fail closed as before.
Failed draining stops owned writers if authority is still live, retains all
published memory, and forbids replay; revoked authority performs no MMIO.
`Report` records addresses, sizes and consumed counts without implying MSI.

Cold boot prepares IH before training and initializes it immediately after
GMC, before command queues. Standalone `ColdBoot::poll_interrupts` provides
bounded polling while that object still owns the rings. The platform handoff
transfers them to the permanent service below after completed boot; subsequent
direct ColdBoot polling is refused. Source-specific fault recovery and fence
dispatch remain separate work; receipt of a raw vector never completes a user fence.

`unsafe amdgpu_navi48_msi::Route::new` prepares a checked MSI capability and
NBIO interrupt-control address without writes/vector allocation. It supports
32/64-bit MSI with optional masking, bounds the complete capability and rejects
overlap, inherited enabled MSI/MSI-X, an unposted PCI function or mismatched
identity. `enable(&mut Rings)` reads the current initialized CPU's actual APIC
ID, refuses IDs beyond legacy MSI addressing and reserves a fresh vector
excluding the fixed `0xf0` TLB vector. It installs the named handler before
programming, selects one message, masks while programming when supported,
checks readback, disables INTx and enables MSI last. PCI Command writes are
16-bit so W1C Status is untouched. NBIO7.7 uses bank5 `0x8e11`; NBIF6.3.1 uses
bank2 `0xf1`. VRAM rings use nonsnoop requests; dummy host reads are explicitly
disabled rather than supplied an invented DMA address. IH storm controls,
ring1 self-IV updates and ring0 rearm/delivery are enabled only after PCI setup.
Every config/register batch invokes current PCI authority. Failed/published
routes retain their vector/handler until independent quiescence.

`amdgpu_navi48_interrupts` owns the transferred rings, route and native fault
monitor behind a separate
async mutex. The final framebuffer handoff starts its executor task; HDMI scans
and firmware/display owner locks cannot delay its draining. The worker snapshots
the IRQ counter before draining, releases its lock before all waits/yields, and
uses a 100 ms watchdog drain in MSI mode. Unsupported/unavailable MSI keeps
diagnosed polling at 1 ms. Partial setup is disabled where authority permits;
an IH arming error fails the handoff with its owners retained. ARM hardware MSI
is explicitly refused until ITS has real ITT backing; register models still
run on both architectures. Fatal draining disables/masks CPU delivery without
recycling a possibly in-flight vector.

`amdgpu_navi48_faults` describes VM and command fault diagnostics. The internal
retained monitor validates exact GC12.0.0/12.0.1/MMHUB4.1 banks without writes during
boot preparation. Service handoff retains all three owners before enabling
sources. It requires active, nonretrying VMID0 in both hubs and the matching
GMC owner in `ClientsReady`. `Gmc::fault_contexts` verifies the exact permanent
register mapping and freshly reads every client VMID's root, start/end page
and native nonretrying control in both hubs. All fifteen must still point at
that owner's empty root, covering the GMC12 client aperture, before any client
submission. Changed/inherited contexts and inherited interrupt enables are
refused. Handoff does not disable or adopt an unexpected active context.
It enables the seven VM protection-fault classes for VMIDs 0..15 on both
hubs, plus bad-opcode/privileged-register
faults for the owned graphics and compute pipes and privileged-instruction
faults for graphics. It also enables the graphics/compute EOP sources and
SDMA0 traps after the cold-start copy has drained; queue proofs only read
those controls, so their setup cannot race fault masking.
Readback is checked after each write. Only the owned fault IRQ fields change
in client controls; page-table roots, aperture, depth, retry and default-page
policy stay fixed. Partial-publication tracking covers all 35 source controls,
so failure/containment masks every published client source as well as VMID0,
CP faults and SDMA traps. Unrelated bits and EOP enables are preserved.

GC/client 0x0a and VMC/client 0x12 source zero select their respective VM hub.
The monitor decodes the IV's 48-bit page address, write/retry flags and retains
the full VMID/PASID/node/queue payload. It snapshots the selected hub's protection
latch, including its separate VMID and client, before posting its self-clearing
acknowledgement. An IV indicating GFX VMID source performs Linux's fast-GRBM
dummy-read sequence.
The latch can refer to a concurrent fault, so it is not attributed to the IV's
process. GC sources 183/184/185 classify bad opcodes, privileged registers and
privileged instructions using native ME/pipe/queue bits. Other sources remain
raw diagnostic events; they cause no monitor MMIO.

The first recognized fault masks all owned fault sources and SDMA0 traps and makes the monitor
`Contained`; this masks reporting and does not establish engine quiescence.
Already-queued VM faults are still recorded and acknowledged.
`Status::faults` exposes the count, last typed record, monitor state and any mask
failure. These survive history consumption and eviction. MMIO/revocation errors
retain the raw vector, stop owned sources where possible, disable CPU delivery,
and leave uncertain hardware/storage retained. EOP proofs reject any recognized
fault or a monitor that is not armed. The monitor itself performs no reset,
PTE repair, fault replay, process termination or allocation reuse.

After containment the platform coordinates graphics, compute and SDMA0,
plus the retained VCN0 unified queue when native media clients are enabled.
A shared blocked flag immediately gates client
and kernel-clear submissions and freezes client retirement, including readers
that do not take the platform owner lock. Under OWNER the watchdog freezes
every ledger before awaiting a service recovery receipt. The receipt binds
the current IH generation and fault-monitor recovery mark, and records each
ring's successful reset and new fence test. A partial or stale receipt cannot
re-arm sources. Cancellation retains `Recovering` and frozen ledgers.

Before re-arm the independent service drains bounded old IH batches and sweeps
both protection latches. Late fault evidence joins the recovery scope. VM/shader
faults in VMID0 or unsupported contexts, foreign queues, poison, terminal
dispatch state and queue owners outside this recovery set require explicit device recovery.
Persistent latches, changed controls, revoked authority and uncertain writes
also refuse re-arm. The source monitor checks every owned control against its
saved masked value, then re-enables and reads back all owned masks. Default,
retry, depth and EOP policy remain fixed; current page-table roots may reflect
client VM flushes. `Status::recovery`, `recoveries`, cumulative count and last
record expose pending and historical evidence separately.

Successful re-arm advances every owned kernel interrupt-handle generation.
Old handles cannot complete new work. The final fault scope excludes guilty
nonzero PASIDs from client IVs, across rings and hubs even if their VMIDs
changed. Its VMID union is diagnostic only: a late IV must not blame the new
address space reusing its VMID. A bounded set of 16 distinct PASIDs overflows
to explicit device recovery rather than losing fault attribution. PASID-less
IVs and protection latches cancel pending work only at that VMID on that hub;
the latch has no PASID even when its VMID matches an IV. Queue faults without
client attribution cancel the queue's pending work without establishing guilt. Healthy
jobs replay under their original tickets with forced VM/PASID/context setup.
All ledgers remain frozen until every replay obtains its new physical fence,
then commit together. A replay failure quarantines reporting and every ledger.
Reset-test fences never retire replay buffers or VMIDs. Recognized faults that
arrive during replay contain reporting again and prevent a successful commit.
This is a software-modeled recovery path; physical reset/re-arm acceptance
remains pending, and automatic whole-device reset is still disabled.

With native media clients the recovery receipt includes a fourth retirement
and the exact retained VCN0 registration. VCPU/LMI drain/retirement,
power-down/up, restart and a new transport proof precede global re-arm; the
renewed media handle, a fresh source-119/CPU proof and the session IB test
precede ledger commit.
Restart clears codec context, so every pending media context is cancelled and
no old media IB replays. Jobs in other healthy contexts replay normally.
Uncertain media retirement or interrupt proof quarantines every ledger.
An isolated media timeout likewise cancels its old contexts before bounded
retirement/restart/proofs, and failure requires explicit device recovery.

Synchronous progress skips a frozen ring, including its media registers while
power is off. Reset freezes and reopens ledgers under `READ_GENERATION`,
draining old readers before changing power and draining skipped samples
before reopening. A placeholder zero from a skipped read cannot retire a
new physical sequence at wrap. Old-generation readers never access new BARs.

The monitor also records the remaining GC-client fault sources Linux defines
for GC12 (irqsrcs_gfx_12_0_0.h): CP reserved-bit, semaphore-wait and general
protection faults, the twelve SDMA7 error sources (SRBM write, invalid
doorbell, queue hang, atomic/poll/page timeouts, null page, page fault, VM
hole, frozen engine and both semaphore timeouts, with SDMA instance and queue
from the IV ring ID), SQ error words (illegal instruction and memory
violation with their 21-bit detail). These have no latch to read, so the
full IV is the retained evidence; they contain reporting like the existing
faults. Only VM, CP privileged/opcode and SDMA0 trap sources are actually
enabled by the service; the rest are classified if the IP raises them.
`Status::first` keeps the first fault record (with its latch snapshot and
acknowledgement) beside `last`, so later consequential faults never
overwrite the original evidence.

Poison/ECC vectors (UTCL2 data poisoning, RLC_GC_FED, CP ECC/FUE, SDMA
ECC/SRAM ECC, SQ EDC FUE/FED, VCN5 UVD/DJPEG/EJPEG poison, DF/UMC ECC and
NBIF ATHUB error events) are not faults and never contain, fault an owner or
terminate by themselves. `amdgpu_navi48_ras` does what Linux's amdgpu_ras
does on bare-metal Navi48 and nothing else. `amdgpu_ras_asic_supported`
accepts MP0 14.0.3 and PSP14 has no RAS capability query, so the block mask
comes from the VBIOS: `Caps::from_vbios` reads umc_info's ECC-capable bit
(v3.1–v3.3, v4.0) and firmware_info's SRAM_ECC capability, and `hw_enabled`
reproduces `amdgpu_ras_check_supported` (mem ECC → UMC|DF; SRAM ECC → every
other block except VCN/JPEG and XGMI). A consumer board reporting neither has
RAS disabled. `disposition` then follows the IP handlers: GFX12, SDMA7,
UTCL2 and JPEG5 register no poison source and KFD v11's ISR drops them;
VCN 5.0.0's UVD_POISON handler returns without a VCN RAS object; the ATHUB IV
is a dummy. These are counted with first/last IV evidence in `ras::Status`.
Only with UMC RAS on (VBIOS mem ECC and UMC 8.14) does the DF ECC IV run
`amdgpu_ras_interrupt_umc_handler`: FED is set, every UMC 8.14 channel's
GeccErrCnt is read through NBIF 6.3.1's RSMU index/data pair and retained,
then cleared; an uncorrectable count is `ras::Fatal::Umc`. UMC 8.14 has no
error-address query, so no page is retired. With DF RAS on, the service polls
BIF_DOORBELL_INT_CNTL after every IH pass as
`amdgpu_ras_interrupt_fatal_error_handler` does; a set ATHUB status is
cleared after capture and is `ras::Fatal::Athub`. Arming mirrors
`amdgpu_umc_ras_late_init` (boot counts read and cleared, GeccErrInt = APIC)
and `soc24_common_late_init` (ATHUB event enabled). Only the first fatal
event counts (`amdgpu_ras_in_intr`). The service stops with
`Terminal::Ras(fatal)`, and the platform's terminal-fault path performs the
mode-1 device recovery Linux's `amdgpu_ras_reset_gpu` requests. The RAS TA
feature-enable command is not sent; Linux falls back to the same software
object when the TA refuses it.

After a lost batch the service wakes every dispatch owner to re-check its
fence and runs `sweep`: both hub protection latches are read (GC first
with its dummy read) and a set latch is recorded as `Kind::Latched` with
no IV, acknowledged after capture, and contained like an IV-reported fault.
Its latch VMID is the only context evidence, so the dispatcher faults every
owner in that VMID. A latch that is non-zero without any fault (for example
inherited from firmware) would therefore contain the monitor after an
overflow; this errs towards fault reporting. Vectors in the resumed backlog
can predate a recovery, but they can only wake owners or fault the current
generation of the same queue key.

`Status` exposes the IH state/report, MSI setup outcome, receive/eviction counts,
sticky last VM-fault vector, two kernel EOP counters and an SDMA0 trap counter. EOP classification
requires SOC21 GC/source 181, VMID/PASID zero and exact ME/pipe/queue identity:
0/0/0 for graphics or 1/0/0 for compute. Doorbell payload is not used to select
kernel queues; reserved ring bit 7 is ignored as in Linux. SDMA classification
requires GC/source 49, VMID/PASID zero and exact instance 0 / queue 0 (ring ID
zero, including bit 7). User SDMA fence source 70 cannot complete this proof.
The counters survive
history consumption/eviction. A 64-entry diagnostic history records complete
raw events; overwrites increment `evicted` and do not erase sticky fault data.
Platform `poll_interrupts` consumes up to 32 history entries, independently of
hardware draining. This history is not an application completion queue.
Platform diagnostics include this live service state separately from boot's
startup report. Hardware MSI delivery still requires a physical-card test.

`amdgpu_navi48_sources::classify` is the single, MMIO-free decoder of SOC21
vectors into typed classes: CP EOP (exact ME/pipe/queue slot plus the
user-queue doorbell in source data 0), SDMA traps (instance/queue) and SDMA
user fences (doorbell >> 2), faults, poison, DCN401 display events, SQ
messages, VCN5 media traps, SMU-owned thermal/SMUIO/MP1 sources, the IH
self-IV and `Unknown`. Display decoding follows `to_dal_irq_source_dcn401`:
source 9 with context 0–5 is HPD and 6–11 HPD-RX, plus OTG VSTARTUP (vblank),
vertical interrupt 0, HUBP flip, VUPDATE-no-lock and the DMCUB outbox.

`amdgpu_navi48_dispatch` delivers classified vectors to registered owners,
following amdgpu_fence.c. An owner registers a `Key` (CP slot, SDMA
instance/queue, VCN unified instance or non-zero user doorbell) with its VMID and PASID and gets a
`Handle` carrying the slot generation. A vector only wakes the owner: `wait`
snapshots the endpoint, calls the owner's own memory-fence check, and parks
until the endpoint changes or a 100 ms watchdog fires (Linux's fallback timer
role); every wait also takes a mandatory deadline. Completion vectors match
the exact slot first and then the doorbell, as gfx_v12_0_eop_irq does, and
must carry the owner's VMID/PASID. Vectors for unregistered, retired or
mismatched owners and unknown sources are counted without completing work;
unknown, unregistered and malformed vectors return `Delivery::Unhandled`
(`Counters::unknown`/`unhandled`), and the first and latest unowned,
unattributed or unhandled IVs are kept in `Summary`. The service writes the
first 16 such vectors to the console (`Status::logged`). Registration and
routing accept only identities Linux has rings for: CP ME 0–2, SDMA
instance 0/1 queue 0 (a trap naming instance > 1 or another queue is
unhandled, as in `sdma_v7_0_process_trap_irq`), VCN client instance 0/1 and
JPEG on the VCN client only (`jpeg_v5_0_0` registers nothing on VCN1).
VCN sources other than 119 and 160 and JPEG sources other than 153 are
unhandled. A CP privileged/opcode fault goes to the kernel ring at its slot
alone; only without one does the context-ID doorbell name a user queue, and
then only in the IV's PASID (`amdgpu_userq_process_reset_irq`).
VCN source 119 wakes its registered unified owner, identified by client
instance plus VMID/PASID as in `vcn_v5_0_0_process_interrupt`; its ring payload
has no separate queue selector. Other media, power and SQ messages remain
diagnostic. Per-endpoint statistics separate signal and watchdog wakes and
count completions first seen by the watchdog, the lost-interrupt evidence
Linux warns about. Waiter storage is bounded (eight per endpoint); an
overflowing waiter still completes through the watchdog and is counted.

Faults are delivered to their owners: CP faults by slot and then the
context-ID doorbell (amdgpu_gfx_handle_priv_fault), SDMA faults by
instance/queue, and VM and shader faults to every owner of the faulting
nonzero PASID even after VMID changes. PASID-less vectors and latches match
only the faulting VMID on its hub (VCN on MMHUB, CP/SDMA/user doorbells on
GFXHUB). The first fault is kept; waiters on a faulted endpoint return
`Faulted` unless their fence already completed. `unsafe recover` is the
controlled-recovery step: once the owner has reset or unmapped its queue it
gets a new generation, and every handle of the faulted generation is `Stale`
forever. Faults without an owner are counted as unattributed. Poison IVs
are counted (`Counters::poison`) and delivered nowhere; a RAS event that
Linux answers with a mode-1 reset reaches waiters as `Terminal::Ras`. The
interrupt
service delivers its own failures (all-ones MMIO as `DeviceGone`, overflow,
protocol, revocation, fault-monitor errors) with `fail_all`: every current
waiter wakes with `Terminal`, new waits return it without reading memory, and
registration is refused. The service registers the kernel graphics
(ME/pipe/queue 0/0/0), compute (1/0/0) and SDMA0 queue-0 owners for VMID0, and
`Status` exposes them with the dispatch summary. The optional VCN proof
retains a separate registration through source enable, execution, shutdown
and power-down. Application jobs share the owned kernel queues; MES user
queues and user doorbells are not published. Coordinated queue recovery and
fault re-arming are described below; late contained faults remain evidence.
Everything here is model-tested (fake vectors and a local table driven
through pending waits); none of it has run on the card.

Display events are counted in `DisplayEvents`, HPD by connector and OTG/
HUBP events by the pipe index their instance backs (`PipePool::pipe`; a
fused instance's event is unhandled), and are
never acknowledged by the dispatcher, because the DCN registers belong to the
display owner (amdgpu_dm acknowledges in `dc_interrupt_ack`). `wait_display`
takes an interest mask (hot-plug, flip, VUPDATE, vblank, VLINE0, DMUB outbox)
and the consumer's last-seen version, so an event between two waits is
reported at once. Overflows and terminal errors wake every display waiter.
The display monitor arms and acknowledges HPD/HPD-RX sources; flip and
vblank completion remain polled by their owners.

The worker's `Status::wakes` separates drains after a CPU MSI, MSI wakes
that found nothing, drains after the 100 ms MSI watchdog, watchdog drains
that found vectors (a lost or unrearmed MSI) and timer polls without a
route. On the card, a working MSI route shows `irq` advancing with
`watchdog_found` staying zero; these counters and the dispatch per-owner
watchdog completions are the evidence the physical test must collect.

`unsafe amdgpu_sdma_navi48::Sdma::new` selects SDMA7.0.0/1 on GC12.0.0/12.0.1,
with queue registers in GC bank zero and MCU control in bank one. Its owned
VRAM ring/writeback allocation is validated against BAR0. `initialize(gmc)`
requires the same GPU's ready GMC owner and rejects all eight inherited
SDMA0 queues. Cold start halts the MCU without a GRBM reset, preserves PSP's
firmware, programs a privileged VMID0 direct ring and submits write, copy
and uncached fence packets. Success requires matching source/destination
bytes, fence, hardware read pointer and read-pointer writeback. HDP6 uses
generic posted-write flushing with no HDP5 invalidate access. A failed or
cancelled attempt cannot replay and retains its published allocation.
The cold-boot owner retains GMC and SDMA throughout their consumers' lives.

After service handoff, `unsafe Sdma::prove_interrupts(gmc).await` appends an
uncached 32-bit fence followed by a native SDMA7 TRAP with zero context, padding
the second submission to 64 bytes. Preflight requires the original 128-byte
hardware and writeback pointers, the matching flat aperture, an enabled ring
and the service-owned trap enable. The separate fence slot is cleared before
publication; it does not overwrite either GC12 proof. Success requires the
fresh fence, both hardware and writeback RPTR at 192 bytes, exactly one new
matching IH trap, and an advancing CPU IRQ count when MSI is configured.
`InterruptProof::msi_verified` distinguishes actual CPU delivery from polled IH
observation. Faults, duplicates, routing changes and a one-second timeout fail
closed. `InterruptSubmitted` is set before the first await; cancellation and
failure prevent replay and retain published storage. `interrupt_result()`
retains success/error separately from the initial copy proof.

The platform's post-boot task serializes this proof after both GC12 interrupt
proofs succeed, with the independent IH consumer still running. Cold-boot
accessors and platform diagnostics expose `sdma_state` and `sdma_interrupts`.
This verifies only the owned bootstrap ring; application submissions, SDMA
fault dispatch, reset and physical interrupt validation remain open.

`amdgpu_dmub_firmware::Image::prepare_dcn401` requires a DCN4 combined image
and allocates a separate, bounded shared-state region alongside the existing
instruction/stack/VBIOS/mailbox/trace/state regions. Shared feature counts must
fit their advertised storage; allocation is at least six 256-byte blocks.
Older layouts continue rejecting images that require shared state.
`amdgpu_dmub_navi48::Prepared::new` prepares immutable ordinary RAM with this
GPU's VBIOS before any hardware write. `unsafe Dmub::new` validates the pool
mapping and retains all nonsecure storage. `quiesce` requires STOP response,
GPINT acknowledgement and PWAIT, then holds CNTL2 and DMUIF reset with readback.
`unsafe start(psp)` verifies both authenticated CW0/CW1 windows lie inside
this GPU's retained TMR, preserves those windows, uploads nonsecure data and
programs Region6 shared state plus the cached windows and mailbox registers.
It requires fresh boot status followed by matching GPINT firmware version and
feature-capability acknowledgement. Initial boot options disable automatic
clock/IPS power transitions and skip the inherited panel initialization.

DCN4 reuses the bounded inbox/outbox protocol for `hpd`, `aux` and
`poll_notification`, with CNTL2 liveness and HDP6 coherency. Timeout, malformed
reply, cancellation, reset or capability revocation stops further commands;
published storage remains quarantined until independent recovery. The
cold-boot firmware bundle includes DMUB preparation, and `ColdBoot::dmub`
exposes the mailbox only after the complete boot sequence succeeds while
retaining PSP/TMR. This proves firmware communication, not native scanout.

`unsafe amdgpu_navi48_platform::prepare(physical_boot_framebuffer)` is the
single-CPU boot handoff. It prepares immutable firmware, inventories VRAM and
refuses training over live firmware in the overwritten prefix, then claims
exclusive controller access and retains `ColdBoot` in an async mutex. Errors
before the claim perform no hardware writes and release all reservations.
On x86_64, the preflight first establishes the calibrated TSC duration scale;
`Error::Clock` refuses preparation before GPU ownership or device writes if
no source is available. Frame's later timer-IRQ setup is not a prerequisite.
Preparation now selects unified MES and retains the matching PCI function.
After the DMA proof, startup maps BAR2 as Device memory (failing instead of
falling back to an unmapped physical address), starts MES12 and records its
report before starting DMUB. BAR sizing is deferred until after the handoff.
`unsafe run().await` requires CPU framebuffer writers to remain stopped; its
owner persists across success, failure and cancellation. `status` exposes the
stage and successful report without waiting. HPD/AUX/notification wrappers
serialize access to the live DMUB mailbox. Normal controller and legacy PM
entry points cannot access either claimed discrete generation; immutable DRM
discovery remains available and acceleration is still unadvertised.

The final `narf-fb` `amdgpu-discrete-firmware` initcall selects Navi22 or Navi48,
pauses CPU console/framebuffer writers before preparation, and runs startup
without a spinlock or executor poll on the stack. A preflight error resumes
writers. A started failure/cancellation on the primary GPU keeps them stopped;
an unrelated secondary GPU cannot quarantine another device's framebuffer.

### Navi 48 variable refresh (DP Adaptive-Sync / HDMI FreeSync)

`amdgpu_freesync` is the shared, integer-only VRR policy (Linux drm_edid.c,
amdgpu_dm and modules/freesync). `monitor_range(edid)` is
drm_get_monitor_range over the whole EDID: EDID 1.4 with continuous
frequency only, every detailed block of the base block, CTA-861 extension
DTD areas and VTB extensions, "range limits only" (flags 0x01) descriptors
with the 1.4 +255 offsets, the last one winning; `None` when none qualifies.
`dp_sst_caps(edid, dpcd)` is amdgpu_dm_update_freesync_caps for a DP SST
sink: DPCD 0x007 bit 6 (MSA_TIMING_PAR_IGNORED) and a range more than 10 Hz
wide give a `VrrRange`. When either monitor-range bound is zero, the
first declared DisplayID extension is searched for the dynamic video timing
range (tag 0x25, revision 0/1, length 9), including the revision-1 upper Hz
bits and Linux's complete-block guard. Undeclared/truncated blocks cannot
supply a range. `VrrRange::supports(timing)` is vrr_supported
(drm_mode_vrefresh within the range). `drr(timing, range)` is
mod_freesync_build_vrr_params for VRR_STATE_ACTIVE_VARIABLE on DCN401: the
minimum is raised to the hardware floor (pixel clock over h_total times
32767 minus the front porch plus one), the maximum capped at the nominal
refresh, the exact-2x rule applied, and fewer than 10 Hz left is fixed
refresh (`None`). `v_total_min` comes from the maximum and `v_total_max`
from the minimum refresh through `calc_v_total_from_refresh`, whose
stream-limit arguments amdgpu_dm leaves zero (so it rounds up), never below
the nominal total. Totals above 32767 are refused as
dc_stream_adjust_vmin_vmax does.

HDMI discovery sends the first declared CTA extension to the authenticated
DCN401 DMUB's EDID_CEA parser (command 79, exact packed 16-byte payload,
sixteen 8-byte chunks). One mailbox lease covers the entire parser sequence;
ACKs must name the submitted offset. A consumed unchanged command is an
unsupported optional query and supplies no range. Failed protocol/transport
or cancelled parsing retains the mailbox/probe owner. `Sink::amd_vsdb`
records the firmware-returned version/range/MCCS VCP code. `AmdVsdb::range`
requires nonzero bounds more than 10 Hz apart and a zero VCP code. Native
HDMI selection and connector capabilities use `Sink::hdmi_vrr_range`: a
nonzero VCP additionally needs this discovery's `mccs::Negotiated` proof.
`Sink::generation` is a fresh, nonwrapping identity for each MCCS discovery;
proofs from old scans, different sinks or different metadata do not authorize
a new snapshot. Running streams retain their old snapshot until retirement.
Sink identity and validated EDID remain required.

`unsafe Ddc::new` retains the shared DCN4 I2C arbitrator. `Ddc::mccs(channel,
generation, metadata)` keeps that claim across the complete native HDMI
negotiation and scheduler sleeps. Its raw I2C address0x37 operations have no
synthetic register offset. `amdgpu_ddc_mccs` follows VESA DDC/CI1.1 §§4.1,
4.3–4.6 and6.3: request/reply checksums use0x6e/0x50, fragment lengths and
big-endian offsets must match, and only a complete, balanced capabilities
string advertising the exact vendor VCP permits Get/Set. Empty-data fragments
terminate assembly; trailing spaces/NULs are trimmed only afterward, with
wire offsets unchanged and interior NUL rejected (as ddcutil's reader).
Concatenated two-hex feature codes and balanced structured value lists are
accepted; nested values never establish feature support. Responses are at
most38 bytes, capabilities at most1024 bytes; NULL/NACK/bad-frame retries
are bounded to three, with scheduler delays respecting40ms Get and50ms
capabilities/Set intervals. A new owner waits50ms before its first packet
so local GPU reset never substitutes for the remote command interval.
Uncertain bus completion is never retried.
The matching Get must report Set-parameter type, success and support bit0;
Set sends AMD's upstream value0x0101. This implementation conservatively
requires a subsequent matching Get to echo the whole0x0101 value; Linux
does not separately define an enable-readback bit. Non-echoing sinks remain
at fixed refresh. No nonvolatile Save command is sent.

A completed unsupported/malformed DDC/CI reply is local: DDC restores pins,
releases arbitration and discovery publishes that sink without VRR while
continuing unrelated sinks. Transport uncertainty or cancellation retains
the shared DDC claim and Scanning journal, publishes no partial results,
and refuses reuse until reset. Previously owned stream snapshots and
unrelated GPU owners remain retained. MCCS support is never inferred from
EDID alone. Primary references are amdgpu_dm_helpers.c
`dm_helpers_read_mccs_caps`/`dm_helpers_mccs_vcp_set` and the
[VESA DDC/CI1.1 standard](https://glenwing.github.io/docs/VESA-DDCCI-1.1.pdf).

DP MST remains outside this capability path, matching the primary
amdgpu_dm_update_freesync_caps signal filter. PCON whitelist negotiation,
MCCS negotiation retains its separate discovery contract.

`Selection::vrr` carries a DP SST or parsed HDMI sink's range (`None` for MST
streams); `Selection::vrr_supported()` and `Selection::drr()` give the mode's
answer and totals. `SstOutput::vrr_capable` reports the connector's
capability. Once an SST stream's video runs (8b/10b or 128b/132b),
`start_link` calls `unsafe ColdBoot::set_display_dp_ignore_msa(port,
vrr_supported)` (`Otg::set_dp_ignore_msa`): enable_stream_features reads
DP_DOWNSPREAD_CTRL (0x107), sets or clears IGNORE_MSA_TIMING_PARAM (bit 7)
and writes it back only if it changed (true when written). It requires SST
video, or a scanout on it, on that path (`Busy`, `Invalid` for another
path, `Unsupported` for MST); as in Linux the modeset ignores AUX failures.
Training still writes 0x107 with the bit clear; sink configuration checks
mask the stream-owned bit. The DCN401 stream encoder's MSA is unchanged.

DML21 admission is unchanged and evaluated at the nominal timing. DCN4's
mode-support and programming calculations do not read `drr_config`; only
the PMO's UCLK p-state strategies (FAMS2/DRR) do, and this owner disables
memory clock switching so those strategies are never searched. DRR only
lengthens the vertical blank (`v_total_min` is at least the mode's total)
at the same line time, so every per-line, prefetch, DET and watermark bound
admitted at the nominal timing still holds, and the stutter budget (taken
from the nominal blank) only gains idle time.

`unsafe async Otg::set_drr(pipe, Option<Drr>)` (ColdBoot `set_display_drr`) runs
or stops DRR on a `ScanoutRunning` pipe (`Busy` otherwise), following
dcn10_set_drr and optc401_set_drr's non-FAMS branch. Enabling writes
V_TOTAL_MAX then V_TOTAL_MIN (minus one), OTG_V_TOTAL_CONTROL MIN_SEL and
MAX_SEL with the TRIGA event in SET_V_TOTAL_MIN_MASK (FORCE_LOCK_ON_EVENT
clear, inherited MID selectors and frame count cleared), then OTG_STATIC_SCREEN_CONTROL's TRIGA event
over two frames. Totals below the mode's, inverted or above 32767 are
`Invalid` before any write; unchanged totals write nothing. `Status::drr`
(`DrrApplied`) records the configured totals, actual adjustment, optional MID/BTR state, and the static-screen control replaced.
Disabling clears the selectors first, then restores V_TOTAL_MAX/MIN to
V_TOTAL (fixed refresh exactly as `prepare` programs it; Linux writes zero,
unused once the selectors are clear) and the replaced static-screen
control. Fixed refresh is also restored before fetch stops (scanout stop
and underflow recovery) and before the timing is disabled. A register
failure leaves `Failed` with the record kept, so a later stop still
restores. While DRR runs, `flip` writes OTG_TRIGA_MANUAL_TRIG after the
address update's lock release (optc2_program_manual_trigger, as
commit_planes_for_stream fires it) so the stretched blank ends at the flip;
flip completion evidence is unchanged. Frame waits on a DRR pipe are bounded
by three frames at `v_total_max` plus 5 ms. TRIGA_CNTL is left as reset, as
Linux's DCN401 path does not program it.


`LfcConfig::new(timing, range)` derives BTR's effective minimum/maximum
frame duration, midpoint and capped 2500us hysteresis margin; it requires
an effective range of at least 2:1. `Lfc::preflip` implements Linux
apply_below_the_range's multiplier choice and 2000us drift preference;
`Lfc::vupdate` fixes MIN=MAX for the inserted duration on the first
observed update and restores the configured variable range at count zero.
DP floors and HDMI ceilings duration-to-total, clamped to nominal timing.
DML admission remains at nominal timing, and UCLK must stay pinned.

`unsafe async Otg::set_lfc` / `ColdBoot::set_display_lfc` attach that state to
the matching ScanoutRunning timing and configured DRR range. The platform
converges it when VRR_ENABLED is applied. Actual address flips sample
render cadence immediately before the OTG address transaction, under the
retained display owner. Real FRAME_COUNT transitions advance the repeat
counter: owner-held latch waits service their own frames, while an idle
scheduler task waits for acknowledged VUPDATE notifications with a 500us
fallback and briefly acquires OWNER. Timer ticks and IV payloads do not
count as frames. A missed frame discards the pending BTR cycle and
render timestamp and restores the configured range; counter wrap uses
the hardware's 24-bit arithmetic. Unreadable witnesses or drift in the
owned totals/selectors/static-screen fields fail closed with timing and
fetch ownership retained. A cancelled transaction stays quarantined;
`lfc_progress`'s public idle entry accepts only ScanoutRunning. No address,
surface lease or nominal DML plan is changed by repeating the retained
surface. Disabling DRR, stopping scanout and recovery remove BTR state and
restore fixed timing before releasing timing/fetch ownership. This
service uses the real FRAME_COUNT witness after notification; precise
physical cadence and interrupt delivery still require hardware acceptance.


The independent IH `SERVICE` retains `dcn401_vupdate::Monitor`, owning
OTG_GLOBAL_SYNC_STATUS VUPDATE_NO_LOCK_INT_EN (bit12) and EVENT_CLEAR
(bit16). Discovery bounds the physical OTG register (0x1b88, stride0x80);
PipePool maps pipe indices to live hardware instances and excludes fused
OTGs. Service installation first masks and ACKs inherited VUPDATE sources
on the live pool before CPU MSI delivery. Construction itself does no I/O.
Only an admitted live LFC configuration arms a source. Enable intent is
recorded before MMIO; current capability checks and checked enable-bit
readbacks precede confirmed ownership changes. RMW suppresses other
shared-register clear strobes, preserving their enable fields.

Enable/ACK/mask operations execute synchronously while SERVICE is held;
the only wait is acquiring its regular mutex, with no IRQ-safe lock held.
The service ACKs a live VUPDATE source before dispatch updates/wakes its
per-pipe event consumer. Queued events from a retired source neither read
its possibly gated OTG nor wake a new consumer. Before a newly armed
source, bounded IH drains discard already queued old events while the
source is masked; even a late IV is only a wake, never frame evidence.
Fused events remain diagnostics and cannot touch MMIO or wake a pipe.
The LFC task waits for `dispatch::VUPDATE` outside OWNER, then samples
FRAME_COUNT under OWNER; missing MSI/backend uses the same 500us fallback.
An IH overflow/terminal-loss version resets BTR/timestamp/base timing,
even if an apparent single frame transition was observed.

Changing the configured DRR range or disabling it awaits source masking
before timing writes. Native `set_lfc` awaits source enable/retirement;
a cancelled wait leaves UpdatingStream with old/pending timing ownership,
so idle work cannot resume it. Low-level native timing disable and fetch
stop both await the same source-retirement hook before their first write.
Readback/capability failure becomes `Error::Interrupts(ih::Error)` and
blocks clock/fetch retirement, retaining source and scanout records.
Thus all transport timing-stop paths, underflow recovery and scanout stop
mask before the OTG becomes inaccessible, including caller cancellation.
`SERVICE::stop`, device loss and reset detach also attempt source masking;
a failed mask retains its owned bit and permanent service. Reset detach
returns an error and refuses to drop that service or proceed to power/reset
work until retirement is confirmed. Deferred loss cleanup checks the IH
service generation so it cannot mask a newer GPU epoch.

Native
models cover all16 fuse combinations, enable/ACK/mask ordering, live and
fused dispatch, stale queued events, partial writes, authority loss and
retained ownership. Actual scanout-chain stop/configuration regressions
pause the awaited source hook, prove no retirement write preceded it,
and verify failure/cancellation quarantine and loss-driven cadence reset.

`unsafe Otg::set_drr_mid` / `ColdBoot::set_display_drr_mid` implement
optc401_set_drr's non-FAMS MID-for-MAX branch: MID minus one, replacing
MAX enable (bit2) and a nonzero 8-bit frame count. The total must lie
inside the configured range and concurrent BTR is refused. The retained
MID register and control are checked by subsequent source verification.
Removing MID or DRR clears its selectors/count; fixed teardown also
clears owned MID storage. The current primary FreeSync BTR module has no
MID producer: native BTR follows its MIN/MAX sequence, while MID remains
an explicit finite timing operation with its own owner.

Native tests replay
1286 DP/HDMI steps and exercise frame wrap, repeat timing, missed/uncertain
observations, readback failure, cancelled flips, live drift and MID
lifetime. The full retained scanout-chain model verifies that an actual
DRR-enabled address flip passes source verification and keeps its DML plan.

KMS (`amdgpu_navi48_kms::{apply_routed_vrr, publish_routed_vrr}`) attaches,
as amdgpu_dm does, an immutable "vrr_capable" range 0..1 to every native
connector (`NativeOutput::vrr_capable`, the published sink's capability)
and a "VRR_ENABLED" range 0..1 to every CRTC (`Card::vrr_enabled`, the
committed values, kept across republication). `apply_routed` attaches
neither, so Navi22 and other cards are unchanged. GETPROPERTY reports both
(vrr_capable RANGE|IMMUTABLE, VRR_ENABLED RANGE); GETCONNECTOR and
OBJ_GETPROPERTIES list them with their values on objects that have them.
VRR_ENABLED is set by DRM_MASTER through OBJ_SETPROPERTY on a CRTC (an
atomic driver's legacy path; connector SETPROPERTY never reaches it) or an
atomic commit (no ALLOW_MODESET needed; TEST_ONLY applies nothing). Values
above 1 and CRTCs without the property are EINVAL, vrr_capable is
immutable (EINVAL), unknown objects ENOENT. OBJ_SETPROPERTY finds its
object as drm_mode_object_find does: by id, of the given type or of any type
for `DRM_MODE_OBJECT_ANY` (0); a type the object is not, or no such type,
is ENOENT, and an object without properties (encoder, framebuffer, blob)
EINVAL. As in Linux, enabling VRR on a
sink or mode that cannot vary is accepted and the display stays fixed.
A committed value goes to `amdgpu_native_kms::request_vrr_enabled` after the
card lock is released (Navi22 ignores it), then
`amdgpu_navi48_platform::request_vrr_enabled`, which records it and schedules
the serialized async stream updater to reprogram each live scanout's DRR
(`Selection::drr()` while VRR_ENABLED and the CRTC is on, else fixed) with
no modeset; the display monitor converges the same at the end of every
pass, including after a relight.

`info_packet(timing, range, hdmi, active)` builds the ordinary AMD FreeSync
v1 SPD (the primary non-PCON/non-replay packet), using the same effective
range as the totals: HDMI header 83/01/08/00, DP header 00/83/1b/04,
AMD OUI 0x00001a, supported/enabled/active bits, rounded min/max Hz and
checksum. Disabled VRR sends nominal min=max. `unsafe async
Otg::set_freesync` / `ColdBoot::set_display_freesync` bind this packet to the
same live display's timing: TMDS/FRL generic packet 3 or DP DIO/HPO packet 2,
with immediate VPG publication and owned transmission enables. HDR, VSC,
audio and DSC keep their separate packet slots and enables. Packet
publication intent is retained in `Status::freesync`; only successful
completion marks it complete. A dropped update leaves Failed/Busy with its
DRR and intent retained, requiring owner recovery. Fixed refresh/scanout
retirement disables the FreeSync packet before releasing fetch/timing. HDMI
control snapshots include the SPD line register and clear SPD/HDR at link
stop. The live updater and monitor both converge timing plus packet state.

Kernel tests replay
its complete packet bytes and exercise all four native encoder routes,
DisplayID/HDMI capability refusal, bad ACK and cancelled parser/publication.

All of this is model-tested only (`drivers/gpu/freesync`, `dcn401-otg`,
`dcn401-scanout`, `navi48-modeset`, `navi48-kms`, `drm_ioctl`); it has not
been validated on hardware.

### Navi 48 color management and HDR output

CRTC color follows amdgpu_dm on DCN 4.0.1 with no plane color properties.
`amdgpu_dcn_color` is the integer port of the Linux math: `Fixed31_32`
(dc_fixpt, bit-exact), `DrmColorLut::from_bytes`, `is_lut_linear`
(__is_lut_linear), `regamma_tf` (256 entries: __set_legacy_tf's sRGB-based
mod_color_calculate_regamma_params with the user ramp; 4096 entries:
__set_output_tf's linear-base mod_color_calculate_degamma_params with
apply_lut_1d), `translate_curve_to_hw_format` /
`regamma_pwl` (cm3_helper_translate_curve_to_hw_format for the 13-region
SDR layout, then custom floats), `Pwl::registers()` (the
cm_helper_program_gamcor_xfer_func words) and `ogam_lut_passes()`
(mpc3_program_ogam_pwl), and for the CTM `ctm_from_bytes`, `ctm_matrix`
(__drm_ctm_to_dc_matrix, sign-magnitude S31.32 to 3x4) and `gamut_remap`
(mpc401_set_gamut_remap's S2.13/S3.12 choice and convert_float_matrix).
The PQ/HLG layouts, degamma
curves and GAMCOR LUT are not ported because the CRTC properties never
reach them on DCN 4.0.1.

`ColorProgram { pre_degam_srgb, gamut: Option<GamutProgram>, ogam:
Option<OgamProgram> }` is what a CRTC programs. `ColorProgram::from_crtc(ctm,
gamma_lut)` maps blobs as amdgpu_dm_update_crtc_color_mgmt and
amdgpu_dm_update_plane_color_mgmt do: a 256-entry GAMMA_LUT is legacy gamma
(sRGB-based regamma, the plane input linearized by the PRE_DEGAM ROM of
its format's implicit degamma, sRGB or an NV12 plane's BT.709, see "Plane
input color", whatever its values); a 4096-entry one regammas unless it is linear, which
like no LUT bypasses the OGAM; any CTM is a gamut remap. On each of a
display's pipes (both ODM halves; with overlays, the gamut remap and regamma
on each segment's top MPCC only and bypass below it, the input transfer
function on every plane's DPP), in dcn401_program_pipe's order:
dcn401_program_gamut_remap (MPCC_OGAM gamut remap in the set not current,
then its mode and format; both MCM remaps bypassed), dcn32_set_input_transfer_func
(dpp3_set_pre_degam sRGB or bypass, GAMCOR bypassed, CM on) and
mpc3_set_output_gamma (memory forced on, the RAM bank not current, its
START/SLOPE/END/REGION words, one or three LUT passes, then SELECT).
`unsafe Otg::set_color(pipe, Option<Arc<ColorProgram>>)` (ColdBoot
`set_display_color`) records a display's color; the scanout start programs
it under the OTG master lock so it latches with the plane, and a
`ScanoutRunning` pipe is reprogrammed at once under the same lock
(`State::UpdatingStream`; cancellation or failure quarantines) and waits
for the latch, as amdgpu_dm's non-modeset update does. `Status::colors`
(`PipeColor`) records each pipe's selections; the DPP, MPC and scanout
verifiers check against it and staging resets it to bypass.

KMS (`amdgpu_navi48_kms::apply_routed_native`, `Card::crtc_color`) gives
every Navi 48 CRTC amdgpu_dm's `drm_crtc_enable_color_mgmt(crtc, 0, true,
4096)`: "CTM" and "GAMMA_LUT" blobs and the immutable "GAMMA_LUT_SIZE"
(4096); DEGAMMA_LUT is not attached (amdgpu_dm_crtc_init omits it on
DCN_VERSION_4_01). GETCRTC reports gamma_size 256. CTM blobs must be 72
bytes, GAMMA_LUT blobs whole drm_color_lut entries numbering 4096 or 256
(amdgpu_dm_verify_lut_sizes), unknown blobs and properties the CRTC lacks
are EINVAL; atomic commits need no ALLOW_MODESET and TEST_ONLY applies
nothing; OBJ_SETPROPERTY sets them too. DRM_IOCTL_MODE_SETGAMMA (master,
not render) copies the ramps into the CRTC's gamma store and commits a
256-entry GAMMA_LUT with the CTM reset (drm_crtc_legacy_gamma_set);
GETGAMMA returns the store; a gamma_size other than 256 is EINVAL, an
unknown CRTC ENOENT. Cards without color management keep SETGAMMA a no-op.
GETPROPBLOB serves user blobs, and a blob a committed property names
outlives DESTROYPROPBLOB until the property lets it go
(`Card::collect_blobs`). A committed change goes to
`amdgpu_native_kms::request_crtc_color` after the card lock is released;
the platform builds the program and a stream updater task (and every
display monitor pass) converges each display.

Every board HDMI and DP connector carries "Colorspace" (Default, BT709_YCC,
opRGB, BT2020_RGB, BT2020_YCC: drm_mode_create_{hdmi,dp}_colorspace_property
for amdgpu_dm's supported set, the same list on both) and
"HDR_OUTPUT_METADATA" (a 32-byte `struct hdr_output_metadata` blob;
another size is EINVAL). MST end-device connectors carry both properties too (dm_dp_add_mst_connector
attaches the root's Colorspace property; amdgpu_dm_connector_init_helper the
HDR metadata property). A new Colorspace or entering/leaving HDR on a driven
connector needs ALLOW_MODESET in an atomic request, as
amdgpu_dm_connector_atomic_check makes it a modeset, while OBJ_SETPROPERTY
and SETPROPERTY on an atomic card commit it (set_property_atomic allows
modesets; only a non-atomic card's set_property_legacy refuses it with
EINVAL); new metadata while
HDR stays on does not. Every native transport signals both, so no lit
stream refuses them.

The selection carries `colorspace`, `hdr` and `vsc_colorimetry`;
`Selection::color_space()` is the stream's dc color space and
`BlankRequest::colorspace` takes it: the output CSC is find_color_matrix's
row for it (RGB types bypass, the identity), the blank black follows
color_space_to_black_color (BT.2020 limited RGB keeps full-range black, as
Linux does), the HDMI AVI InfoFrame its C/EC/Q, DIO/HPO DP MSA MISC0 and
DIO MISC1. DIO DP streams (SST and MST; enc401_stream_encoder_update_dp_info_packets
serves both) on a VSC-capable sink send the VSC SDP in packets 0 and 1
(GSP0) and, with HDR metadata, the HDR SDP in packet 3 (GSP3) before the
unblank. 128b/132b streams (SST and MST) do as
dcn31_hpo_dp_stream_enc_update_dp_info_packets does through the stream's VPG
(`otg::UhbrSdp`, the Otg/ColdBoot UHBR start and MST prepare entries take
it): the VSC SDP in packet 0, the HDR SDP in packet 3, each with an
immediate update, then GSP0/GSP3 continuous transmission for the valid ones
(GSP2/GSP5 off) and the SDP path on, all before the unblank; MSA MISC1 bit 6
marks VSC colorimetry (`amdgpu_hdr::hpo_msa_misc`, the HPO encoder's own
MISC0/MISC1, which start from zero). Ready and transport witnesses recheck
the GSP enables. HDMI TMDS streams send the DRM InfoFrame in generic packet
4 on line 2; FRL streams in the HPO FRL encoder's generic packet 4 on line
2 (`FrlVideoRequest::hdr`, hpo_enc401_update_hdmi_info_packets). An MST
stream's VSC support is the root link's DPCD (create_stream_for_sink reads
stream->link). The packet bytes are the same on every transport (Linux
builds them from the connector type only). `unsafe Otg::set_hdr(pipe,
InfoPacket)` (ColdBoot `set_display_hdr`) rewrites a running stream's packet
with an immediate update (amdgpu_dm's hdr_static_metadata stream update) on
TMDS, FRL, DIO and HPO streams. The platform relights a display whose
connector's Colorspace or HDR on/off changed and updates metadata live
otherwise. DP SST output depth follows amdgpu_dm:
min(the EDID 1.4 color bit depth, 8 when undefined, `max_bpc` rounded to
even), stepping down by two until a link carries the uncompressed stream
(`modeset::dp_depths`, `dp_link_bpc`); training candidates and the UHBR
audio budget use it. With the default `amdgpu.max_bpc` (8, a NARF ceiling
over each connector's "max bpc") DP stays 8 bpc. Gaps: plane color
pipelines and AMD private properties. Model-tested only (`dcn-color`,
`hdr`, `dcn401-color`, `dcn401-scanout`, `dcn401-otg`, `dcn401-frl-link`,
`dcn401-mpc`, `navi48-modeset`, `navi48-kms`, `drm_ioctl`); not validated
on hardware.

### Navi 48 connector max bpc

Every Navi 48 KMS connector, board HDMI and DP and every MST end device,
carries "max bpc": amdgpu_dm_connector_init_helper's (and
dm_dp_add_mst_connector's) drm_connector_attach_max_bpc_property(connector,
8, 16), a RANGE 8..16 property (`MAX_BPC_PROP_ID`, 0x80) whose value is the
connector state's max_requested_bpc, 16 when the connector is created.
`NativeOutput::max_bpc` holds it (None: no property; Navi 22's and the
test cards' connectors keep their lists), `ConnectorProps::max_bpc`
attaches it in `amdgpu_navi48_kms::apply_routed_native`, and a committed
value survives republication. GETCONNECTOR and OBJ_GETPROPERTIES list it
after "Broadcast RGB" and before "Colorspace"; GETPROPERTY reports the
range. A value outside 8..16, or a connector without the property, is
EINVAL (drm_property_change_valid_get). A changed value on a connector with
a CRTC is a modeset of that CRTC (drm_atomic_helper_check_modeset sets
connectors_changed when max_requested_bpc differs): an atomic commit needs
ALLOW_MODESET (TEST_ONLY checks it too), while OBJ_SETPROPERTY and the
legacy SETPROPERTY commit it as set_property_atomic does, whose commit
allows modesets (drm_atomic_commit_init). After the card lock is released,
`amdgpu_native_kms::request_connector_max_bpc(connector, bpc)` records it on
the platform connector (`amdgpu_navi48_platform::request_connector_max_bpc`),
which a lighting hands to the selection
(`amdgpu_navi48_boot::set_requested_bpc(port, mst_slot, bpc)`, one entry per
board port and MST slot, `requested_bpc` reads it) and records per CRTC;
the display monitor relights a display whose connector's value changed
since it lit.

Selection caps each stream with `connector_max_bpc(port, mst_slot)`: the
connector's max_requested_bpc within `amdgpu.max_bpc` (a NARF ceiling,
default 8; Linux has no such parameter, and with `amdgpu.max_bpc=12` the
property alone decides, the native encoders taking at most 12 bpc). It is
the requested bpc of amdgpu_dm_create_validate_stream_for_sink's bpc mask
and of convert_color_depth_from_display_info (rounded down to even): DP SST
and HDMI (`select_all`, which applies each port's own value, offered and
retrained modes), MST DSC (`MstDscContext::max_bpc`, now a per-end-device
function) and uncompressed MST. On an MST link without DSC decoders each
stream is `raw_mst_stream`: the deepest of its depths whose raw bandwidth
dm_dp_mst_is_port_support_mode accepts (`dsc::raw_supported`: within the
root link and the port's full PBN), with dm_encoder_helper_atomic_check's
payload, drm_dp_calc_pbn_mode at `requested_depth_bpc` (display_info.bpc,
8 when undefined, capped by max_requested_bpc and rounded down to even) and
its slots, however far the stream stepped down; the VC rate and LPCM budget
are the stream's own depth's (DC's get_pbn_from_timing).
`MstStream::pbn_bpc` records the depth the PBN was sized for (the stream's
own on a link the fairness search sized), which a running stream's offered
modes are measured with. A stepped-down stream whose requested-depth PBN no
longer fits its port is refused, as Linux's drm_dp_mst_atomic_check refuses
it. Deviations: 6 bpc (an EDID 6-bpc sink
gets 8 bpc, its PBN 8 bpc's), 14 and 16 bpc are never streamed (the PBN of
a 14- or 16-bpc request is Linux's); offered modes of a dark connector
follow a new value at the next lighting; the property is per connector but
"Broadcast RGB" stays one setting for the card. Model-tested only
(`drm_ioctl`, `navi48-kms`, `navi48-modeset`, `navi48-mst`); not validated
on hardware.

### Navi 48 plane scaling and overlay planes

**SPL and DSCL.** `amdgpu_dcn401_spl::calculate(&Input) -> Scaler` is the
integer port of DC's SPL (dc/sspl `spl_calculate_scaler_params`) with
DCN401's configuration: SPL on, EASF preferred, iSHARP off, linear-light
scaling for RGB (EASF with six taps while the ceiling ratio is at most 2,
polyphase otherwise), `max_downscale_src_width` 7680 and the 12-pixel
`MIN_VIEWPORT_SIZE`. It computes the recout, MPC size, ratios, inits, taps,
luma/chroma viewports, polyphase filters and EASF coefficients in dc_fixpt
arithmetic (`amdgpu_dcn_color::Fixed31_32`), with the filter tables
generated from Linux (`amdgpu_dcn401_spl_filters`). `Scaler::unity` is the
bypassed full-frame segment. `amdgpu_dcn401_dscl::program(&Scaler, alpha)`
returns dpp401_dscl_set_scaler_manual_scale's register sequence (SCL mode,
ratios/inits/taps, coefficient RAM loads with the SCL_COEF_RAM_SELECT swap,
EASF, the line buffer of dscl401_spl_calc_lb_num_partitions /
dpp401_dscl_find_lb_memory_config), and `viewport()` returns
hubp401_set_viewport's words (chroma equal to luma for RGB).

**Placed planes.** `otg::SurfaceRequest::plane: Option<PlaneLayout>`
places a surface on its stream as amdgpu_dm_plane_fill_dc_scaling_info hands
DC a plane: the source rectangle, the destination on the stream (the clip is
the destination), the stream's size and 4:2:0 encoding, the rotation (0,
90, 180 or 270, DC's ROTATION_ANGLE; a linear surface at 90/270 is
`Unsupported`, as DML refuses a linear surface scanned vertically,
`Rotation::orthogonal`), the blending (`Blend`: per-pixel alpha, premultiplied, global alpha) and
`underlay`. `None` is the unscaled full-frame primary (each ODM segment
`Scaler::unity`). Each segment's SPL input is its ODM slice
(resource_get_odm_slice_src_rect) and must succeed
(resource_build_scaling_params), and some pixel must land on the stream,
else `Unsupported` or `Invalid` (`SurfaceRequest::check`). The HUBP takes
SPL's viewport and ROTATION_ANGLE, the DPP the DSCL program (the iSHARP LUT
ends at Linux's final value), the cursor is placed in recout space
(dcn401_set_cursor_position), and MPCC_CONTROL the blend
(dcn401_update_mpcc_sequence: per-pixel alpha, per-pixel combined with the
plane alpha as global gain, or global alpha; premultiplied unless Coverage).
`SurfaceRequest::dml_plane()` is the plane as DC hands DML21 one after SPL
(whole-stream viewport, ratios and taps). A restage reuses the buffers of
the same pipe, size and format whatever the placement.

**Overlays.** A display stacks up to `otg::MAX_OVERLAYS` (3, DCN401's
`max_slave_planes`) overlay planes on free pipes, one per ODM segment of
their stream (or two for an MPC-combined overlay), staged on the overlay pipe through `prepare_surface`,
`prepare_memory`, `prepare_dpp` and `prepare_mpc` under the selected
display's stream (`Engine::stream_pipe`). A memory restage keeps the other
planes' records when the VMID0 context is unchanged, and staging checks
tolerate the display's own pending staged addresses (`staged_planes`).
`unsafe Otg::prepare_requestor_planes(.., pipe, overlays, plan: Option<&Plan>)`
(ColdBoot `prepare_display_requestor_planes(.., &Plan)`; overlays bottom first,
underlays before the others) gives every plane's HUBP its DML DET and the
primary's VTG, recording `RequestorApplied::overlays`, `det_bytes` and
`overlay_det_bytes`. Native modesetting always supplies the admitted plan;
`None` retains default 320-KiB storage staging for low-level callers only.
The total must leave compbuf space and each active DET is 2..20 segments;
other displays retain their recorded per-plane allocations. It it refuses an overlay on the
primary's pipes, an unstaged pipe, a pipe used twice, another display's pipe
(`Siblings::pipes`, which counts overlay pipes and DETs) or an underlay above
an overlay (`Invalid`), and a fourth overlay (`Unsupported`). Deadlines
program each plane's HUBPs its plan's DLG/TTU (`dml::Plan::plane_dlg`,
`Plan::plane`) after binding the plan to the plane list (`deadline::bound`:
each surface's `dml_plane`, stream size, ODM and DET); `Otg::prepare_deadlines`
also checks each overlay pipe's DPP-only clock against its plane's DPPCLK.
`start_scanout` builds each ODM segment's MPCC tree as mpc1_insert_plane does
for planes programmed from the top down (each new MPCC at the bottom over the
background, TOP_LAYER_ONLY; the one above it switched to TOP_BOT_BLENDING;
the top MPCC on the OPP's OUT_MUX; an underlay below the primary, which still
feeds its own OPP), all under the one OTG lock with every HUBP unblanked, and
waits for every plane's EARLIEST_INUSE. `ScanoutRunning::overlays`
(`OverlayScanout`) records them. The CRTC's gamut remap and regamma go on
each segment's top MPCC only (dcn401_program_gamut_remap and
dcn401_set_output_transfer_func's `is_top_pipe`), the input transfer
function on every DPP. `unsafe Otg::flip_planes(.., pipe, mask, ..)`
(ColdBoot `flip_display_planes`) re-addresses any set of planes (bit 0 the
primary, bit k the k-th overlay) under one lock so they latch at one VUPDATE;
`prepare_plane_back_buffer` and `upload_plane_back_buffer` serve the
overlays' back buffers. `stop_scanout` detaches the overlays first (top
down), returning every MPCC to TOP_LAYER_ONLY. Live checks (`LivePipe`:
address, cursor, the five tree selectors and the MPCC mode) cover every
plane, also another display's live pipes. `retire_planes` ends overlay
staging (records on pipes with neither timing nor blank of their own) and
returns their pipes and DETs. The cursor shows on every plane's pipe it
overlaps (see the cursor below).

**Admission.** `dml::Mode::planes` lists the stream's planes (`dml::Plane`:
surface, pitch, depth, SPL viewport, ratios and taps; an empty `planes[0]` is
the full-frame primary of `pitch` and `bytes_per_pixel`, overlays follow
from `planes[1]`, `Mode::plane_list`); `admit_all` takes at most
`dml::MAX_PLANES` (4) planes and the pool's pipes in all (`Pipes`). Per plane it
follows dml2_core_dcn4_calcs.c: DPPCLK from the PSCL throughput
(CalculateSinglePipeDPPCLKAndSCLThroughput), DPPREFCLK from the fastest
plane and DISPCLK from the fastest stream, the scaler's DPPCycles, prefetch
source lines from the vertical ratio and taps, the swath and ODM recout width
at the horizontal ratio, active burst at the vertical ratio, line-buffer
hiding with the extra taps and the several-surface share, deep-sleep DCFCLK
per plane, and per-plane DLG/TTU (`Plan::planes`, `PlanePlan`: DPPCLK, DLG,
TTU, DET, ODM blank end; line and request delivery above a vertical ratio of
1 at the scaler's throughput). The plan's top-level DLG/TTU are the
primary's. A
`dml::Plane` also carries its `source` (`Source::Rgb`, `Yuv420_8`,
`Yuv420_10`), `swizzle` (`dml::Swizzle`, DC_ADDR3 linear to 256KB_2D),
`dcc`, `vertical_scan` and a 4:2:0 plane's `chroma` (`dml::Chroma`: half
surface, pitch, SPL's chroma viewport, ratios and taps), as
populate_dml21_surface_config_from_plane_state hands them DML
(`SurfaceRequest::dml_plane`); admission then follows
dml2_core_dcn4_calcs.c for both surfaces (block and macro-tile sizes, luma
and chroma swaths and requests, the DET split and chroma base, two-surface
prefetch, bursts, deep sleep, DPPCLK and delivery, unbounded requesting,
DCC's mcache allocation and overhead; a linear vertical scan is refused, a
plane needing an MPC split for its mcaches takes two DPPs, see MPC combine). `PlanePlan`
adds `rq` (`dml::RqRegs`: luma and chroma `RqPlane`, expansion modes, the
DET plane-1 base, unbounded requesting), `mcache` and the chroma DLG/TTU
delivery fields, which `deadline_writes` programs (the *_C halves of the
per-line delivery registers, SURF1_TTU0/1; for a tiled or 4:2:0 plane
hubp401_program_requestor's HUBPRET_CONTROL plane-1 base,
DCN_EXPANSION_MODE, DCHUBP_REQ_SIZE_CONFIG(_C) and the unbounded-request
bit, which the static requestor check then leaves to it).
A 4:2:0 primary is never
the packed full-frame plane (`modeset::plane_mode` gives DML its explicit
plane).

**Modeset and platform.** `modeset::PlaneSetup` (the primary's
`PlaneGeometry`: source origin and size, CRTC rectangle, rotation, blending;
`OverlayPlane`s bottom first with format and `underlay`) is set per pipe
(`set_plane_setup`, `plane_setup`, `Selection::planes`). `selection_mode` and
`with_planes` give DML every plane (`plane_requests`/`stream_planes` build the
surface requests); every plane takes the pipes DC acquires (`light_pipes`,
see "Pipe acquisition"), refusing `Admission(Pipes)`; `prepare_pipes` gives
each display's head pipe its clocks and its `DisplayPipes` (ODM, MPC and
overlay pipes) their DPP-only clocks; `light` powers, stages (every plane's memory before any plane's DPP)
and requests every plane. The platform records each CRTC's planes
(`request_display_planes`), moves a running display to new planes or a new
primary format without relighting it (see "Navi 48 seamless plane updates";
only what needs a modeset relights, and a failed relight returns every
display to the full-frame XRGB8888 primary), and admits a configuration with
`display_admits_planes(display, connector, mode, fourcc, setup) ->
Result<(), PlanesRefused>`: the display lit on the same connector and timing
(`NotLit` otherwise), DML21 with every lit display's admitted planes
(`Bandwidth`, `Plane`), the pipes DC acquires for every plane of the
configuration lit anew (`plan_pipes`; `Pipes`) and staging's checks
(`Plane`).
`present_planes(display, primary, overlays, ticket)` queues a commit's
`PlaneFrame`s (merged per plane in the mailbox); the presenter copies each
plane's framebuffer source rectangle into its back buffer and flips every
changed plane together.

**KMS.** `drm_native_planes` gives the Navi 48 card amdgpu_dm's planes
(amdgpu_dm_initialize_drm_device, amdgpu_dm_plane_init): each CRTC's primary
(id 0x40 + n) and three overlays (0x44-0x46, possible_crtcs 0xff, the
primaries' `PLANE_FORMATS`, as amdgpu_dm_plane_get_plane_formats gives
DCN4's universal overlays), listed by GETPLANERESOURCES and GETPLANE (an
overlay's CRTC and framebuffer as committed). Properties
(`Card::native_planes`, `PlaneProps`): "pixel blend mode" (None,
Pre-multiplied, Coverage; default Pre-multiplied) on every plane, "alpha"
(0..0xffff) on the overlays, "zpos" (the primary's immutable at 3; an
overlay's 0..254, default 3 + 1 + its DRM plane index after the four
primaries, 8-10) and the "rotation" bitmask (rotate-0/90/180/270, exactly
one); a value outside its property or a write to the immutable zpos is
EINVAL. ATOMIC (TEST_ONLY included) and DRM_IOCTL_MODE_SETPLANE (master;
drm_mode_setplane's atomic path: fb 0 disables, unknown plane, CRTC or
framebuffer ENOENT, a source outside the framebuffer ENOSPC) run
`drm_native_planes::check`: drm_atomic_plane_check's CRTC rules (a plane
moved straight to another CRTC, a primary off its own CRTC) and formats;
amdgpu_dm_plane_helper_check_state (the 24x12 viewport left on the CRTC,
drm_atomic_helper_check_plane_state with DCN401's 16x upscale and 6:1
downscale caps) and amdgpu_dm_plane_fill_dc_scaling_info (non-empty
rectangles, 167..16000 per mille); an enabled CRTC needs its primary
(dm_crtc_helper_atomic_check); rotation 90/270 swaps the source for the
helper's scale limits and is refused on a linear framebuffer (RGB or
NV12/P010: DML21's SourceFormatPixelAndScanSupport scans no linear surface
vertically), while a GFX12-tiled one is placed with its rotation (HUBP
ROTATION_ANGLE, SPL's orthogonal viewport, DML's vertical scan; never
H_MIRROR_EN, as amdgpu_dm exposes no reflect-x/y); drm_atomic_normalize_zpos (zpos, then plane id)
orders the stack, overlays below the primary being underlays; and the
platform's admission. Every refusal is EINVAL (Linux's scale check returns
-ERANGE, which FsError cannot express). A plane change needs no
ALLOW_MODESET. A commit records the planes' state and requests each touched
display's planes; the planes it updates present together (`present_planes`).
PAGE_FLIP keeps a placed primary's placement (the new framebuffer must hold
its source rectangle, ENOSPC otherwise), SETCRTC shows the framebuffer whole
again (drm_atomic_helper_set_config) and RMFB disables the overlays scanning
the removed framebuffer.

**GFX12 modifiers.** `amdgpu_dm_modifiers` is amdgpu's GC 12 modifier
layer. `PLANE_MODIFIERS` is amdgpu_dm_plane_get_plane_modifiers for a GC 12
primary or overlay: amdgpu_dm_plane_add_gfx12_modifiers' twelve DCC entries
(256K_2D, 64K_2D, 4K_2D, 256B_2D, each with max compressed block 256B, 128B,
64B), the four swizzles without DCC, then LINEAR (17; INVALID ends Linux's
list and is not one of them). `format_mod_supported` is
amdgpu_dm_plane_format_mod_supported: LINEAR and INVALID always, a listed
GFX12 modifier for every format (no GFX9-11 D-swizzle/DCC rules). On the
native card (`Card::gfx12_modifiers`) every plane's `IN_FORMATS` and
`IN_FORMATS_ASYNC` blob (`drm_native_planes::IN_FORMATS_PROP_ID` /
`IN_FORMATS_ASYNC_PROP_ID`, blob ids `in_formats_blob_id` /
`in_formats_async_blob_id`, GETPROPBLOB) is create_in_format_blob's
version-1 `drm_format_modifier_blob`: the plane's 19 formats, then the 17
modifiers each with the mask of the formats that take it (all of them); a
card with native planes but no GFX12 modifiers lists LINEAR alone.
`Tiling::from_modifier` is amdgpu_dm_plane_fill_gfx12_attrs_from_modifiers
(swizzle and DCC max block of any GFX12 modifier). ADDFB2
(`Card::addfb2_cmd`, the whole 104-byte `drm_mode_fb_cmd2`:
`amdgpu_dm_modifiers::FbCmd`) on the native card runs
drm_internal_framebuffer_create (flags, 16384x16384, a DRM format,
framebuffer_check: handles, pitches, overflow, per-plane modifiers equal,
unused planes zero), the BO lookup, then amdgpu_display_gem_fb_verify_and_init
(`check_amdgpu_fb`: drm_any_plane_has_format with modifier[0], every plane
in the same BO, without DRM_MODE_FB_MODIFIERS the BO's tiling flags through
convert_tiling_flags_to_modifier_gfx12, amdgpu_display_verify_sizes: each
plane's pitch whole swizzle blocks and at least its width, block-aligned
offsets, whole block rows within the BO, LINEAR in 256-byte units); a
refusal is EINVAL (FsError has no ERANGE). `Framebuffer` records
`offsets`, `chroma_pitch` and `modifier`. `AMDGPU_GEM_METADATA` on one of
the card's dumb BOs (`drm_ioctl_bridge::amdgpu_dumb_metadata`) sets/gets its
tiling flags (`Card::set_bo_tiling`); CREATE_DUMB pads the pitch as
amdgpu_mode_dumb_create does (`amdgpu_gem::align_pitch`, amdgpu_gem_align_pitch;
once the card's client VRAM heap is up its dumb buffers are amdgpu GEM
buffers in VRAM instead, see "Dumb buffers in VRAM"). Other cards keep
LINEAR-only ADDFB2. DCC capability is hubbub401_get_dcc_compression_cap as amdgpu_dm calls it
(`dcc_capable`: every scanned format; GC 12.0.1 has no DCC width limit, GC
12.0.0 refuses DCC above 7680 pixels, from the bound `amdgpu_rdna4` die).

**Tiled, DCC and 4:2:0 surfaces.** `otg::SurfaceRequest::surface`
(`PlaneSurface`: `Tiling` and a `YuvColor`) and `SurfaceFormat::{Nv12,
P010}` (DC's VIDEO_420_YCrCb / 10bpc_YCrCb, as amdgpu_dm maps them;
`is_video`, `chroma_bytes_per_pixel`). `SurfaceRequest::bytes` lays each
plane out as amdgpu_display_verify_plane sizes a framebuffer (pitch of whole
swizzle blocks, whole block rows; a 4:2:0 chroma plane at half size behind
the luma, block and page aligned). HUBP: DCSURF_SURFACE_CONTROL
PRIMARY/SECONDARY_SURFACE_DCC_EN from the modifier (hubp401_dcc_control),
SW_MODE the swizzle (hubp401_program_tiling), PITCH and PITCH_C
(hubp401_program_size), the VIDEO_420 pixel format (64/66), SPL's chroma
viewport, and the chroma address before the luma's
(hubp401_program_surface_flip_and_addr), also on flips and at scanout start
(`Engine::write_fetch_address`). DPP: CNVC_SURFACE_PIXEL_FORMAT 64/66 and,
for 4:2:0, CM_POST_CSC with the color space's dpp_input_csc_matrix
(dpp401_dpp_setup's INPUT_CSC_SELECT_ICSC, dpp3_program_post_csc,
cm_helper_program_color_matrices' packing), double-buffered as
dpp3_program_post_csc does it: the matrix goes into the coefficient set not
in use (B, CM_POST_CSC_B_* with COMA selected, when
that DPP's own CM_POST_CSC_MODE_CURRENT reads A; A otherwise:
`dpp::post_csc_set_b`, chosen per segment DPP as each runs its own setup),
recorded per segment in `DppApplied::post_csc_b` (`dpp::PostCscSets`), so a live color-space change latches
whole at VUPDATE. SPL takes `spl::Video`
(SPL_PIXEL_FORMAT_420BPP8/10): chroma ratios/viewports/inits/taps, the 420
SCL modes, chroma coefficient loads, EASF's video rules, LB config 3; a 4:2:0
plane always goes through `spl::calculate` (its chroma is upscaled even
unscaled). KMS: primaries and overlays carry "COLOR_ENCODING" (BT.601/709/2020,
default BT.709) and "COLOR_RANGE" (limited/full, default limited) as
drm_plane_create_color_properties makes them (they only affect YCbCr; a
value outside the enum is EINVAL). `drm_native_planes::plane_surface`
gives each plane's `PlaneGeometry::surface` (fill_plane_color_attributes'
color space) and `fb_size`; a tiled or 4:2:0 plane, and a plane showing an
amdgpu GEM framebuffer in place whatever its layout (`PlaneGeometry::client`),
is staged as its whole framebuffer with the source rectangle placed in it
(`PlaneGeometry::whole_framebuffer`), as fill_plane_buffer_attributes hands
DC the framebuffer's address and size with the crop in the viewport, so a
linear GEM plane's crop at any byte shows; such a tiled or 4:2:0 primary
is always placed (a linear client primary shown whole is still the
full-frame one); a
dumb framebuffer of it is copied whole, block row by block row
(`copy_whole_plane`, `upload_display_plane_back_bytes`), a GEM one is
scanned out in place (below); a frame of another tiling than shown waits
for the plane update its plane change requested.

**Client framebuffers scanned out in place.** On the native card ADDFB2
also takes one of the calling open's amdgpu GEM handles
(amdgpu_display_user_framebuffer_create's drm_gem_object_lookup in the
file's table: `drm_ioctl_bridge::amdgpu_addfb2_bo`, dispatched by
`DriCardFile` before the card's ADDFB2, then `Card::addfb2_bo`), checked as
a dumb one is but against the buffer's own size, its `GEM_METADATA` tiling
flags (`GemObject::tiling_flags`) and AMDGPU_GEM_CREATE_GFX12_DCC
(amdgpu_display_get_fb_info). `Framebuffer::bo` (`FbBo`: the
`GemObject`, which the framebuffer holds, and the owning open) is removed
with RMFB or, at the open's close, by `Card::release_file_framebuffers`
(drm_fb_release). Showing it (atomic, SETCRTC, PAGE_FLIP, SETPLANE, a
cursor plane or legacy CURSOR) is amdgpu_dm_plane_helper_prepare_fb,
run as drm_atomic_helper_prepare_planes runs it: under the KMS lock
before the commit changes any state (`drm_ioctl_bridge::PreparedFbs::prepare`
for every framebuffer the commit shows; the presenter frames and cursor
requests take its pins). A pin that fails fails the ioctl with its errno
before any CRTC, plane or event changes, and the pins already taken drop
with it (cleanup_fb of the failed commit). `GemObject::pin_scanout` pins the
buffer with
amdgpu_display_supported_domains' domain, which on this dGPU (no
gpu_vm_support) is VRAM alone, DCC buffers included: a VRAM placement is
one contiguous reservation (amdgpu_vram_mgr_new's VRAM_CONTIGUOUS path, so
an AMDGPU_GEM_CREATE_GFX12_DCC buffer is placed as that path places one
wherever it lands in VRAM: GEM_CREATE, past the BAR, and every move back,
`amdgpu_gem::reserve_visible` / `reserve_hidden`): the card's
`amdgpu_gem::gmc_v12_dcc_alignment` (gmc_v12_0_get_dcc_alignment from
discovery's GC version and gc_info TCC count, registered by
`publish_client_vram` through `amdgpu_gem::set_gfx12_dcc`; 64 KiB on
Navi48's 16 TCCs, 0 off GC 12.0.x) rounds the request to the power-of-two
block `amdgpu_vram::dcc_block_size` (roundup_pow_of_two(size + alignment),
in Linux's 32-bit dcc_size), placed at its own alignment, then trimmed to
the buffer's size from the block's first multiple of the alignment counted
from VRAM offset 0 (`amdgpu_vram::dcc_trim_start`, `Pool::reserve_dcc`,
`UnmappedPool::reserve_dcc`; the rest of the block is free again).
The temporary block's alignment is also relative to VRAM offset zero,
independently of the GPU address of that origin. If no whole temporary block
is free, the native range allocator instead reserves the final buffer size
at the first free DCC-aligned start. This remains one contiguous reservation
and preserves the hardware's address/size constraints, for visible and
invisible VRAM. This fallback is more permissive than Linux's rounded
VRAM_CONTIGUOUS path: its ENOSPC retry clears the buddy contiguous-allocation
flag but retains the BO flag and DCC block rounding.
Separate native tests cover fragmented
visible/invisible pools, non-aligned VRAM origins and exhausted aligned starts. A
pinned DCC buffer reports `ScanoutPin::dcc_aligned`, a DCC buffer whose
placement misses the alignment is refused at the pin, and a DCC plane
refuses an `otg::ExternalSurface` without `dcc_aligned`. Linux takes the
DCC placement only once a buffer is allocated VRAM_CONTIGUOUS (prepare_fb
sets the flag, so its first pin re-places a non-contiguous one; a buffer
that happened to land contiguous keeps its start); NARF's placements are
all contiguous, so it applies from creation. The pin never moves a
buffer: amdgpu_bo_pin's validation (a buffer in system memory moving back
to VRAM, which waits for its jobs and copies it whole) runs before, in the
async `drm_ioctl_bridge::amdgpu_kms_async` (below), never under the
KMS spinlock. `amdgpu_gem::prepare_scanout` returns
`Result<ScanoutPreparation, FsError>`; success retains the card's placement
exclusion through the synchronous KMS commit. It protects already-resident BOs
as well as promoted ones: asynchronous movers park, and synchronous pressure
cannot evict between validation and `PreparedFbs::prepare` acquiring pins.
Success, refusal and cancellation release the guard; successful KMS pins
continue protecting the actual scanout. A buffer still outside VRAM is ENOMEM (`OutOfMemory`, as
ttm_bo_validate reports no room); one VRAM is not allowed for or a foreign
dma-buf is EINVAL and a userptr EPERM, as amdgpu_bo_pin answers. A
CPU-accessible buffer is only ever placed in visible VRAM (amdgpu_bo_pin
forces CPU_ACCESS_REQUIRED for one; NARF puts only NO_CPU_ACCESS buffers
past the BAR), and the pin refuses one found past the BAR. `ScanoutPin` (amdgpu_bo_unpin on drop) keeps the
buffer and its placement: while any pin lives `GemObject::pinned` stops
`relocate`, `commit_transfer`, pressure eviction (`evict_visible_locked`) and
`amdgpu_vm::relocate`, and `evict_all` passes the buffer by (TTM's LRU walk
does not see pinned buffers). The presenter frame (`PlaneFrame::bo`) carries
the pin; it waits up to 5 s for the buffer's WRITE fences
(amdgpu_dm_commit_planes' dma_resv_wait_timeout) and flips the plane to the
buffer's own GPU address with no copy (`PlaneFrame::external`: the pin's
address plus offsets[0], pitches[0], the chroma plane at offsets[1] with
pitches[1], from the framebuffer's start, its plane staged whole; only a
GEM frame reaching a plane still staged as a dumb buffer's source
rectangle, until the plane update that restages it, starts at the
rectangle; `place_plane`, `ColdBoot::flip_display_sources`).
`otg::FlipSource` is `Back` (the staged back buffer the presenter copied a
dumb framebuffer into) or `External(otg::ExternalSurface)`;
`Surfaces::flip_sources` re-addresses every flipping plane under the one OTG
lock and, when a client framebuffer's pitch differs from the plane's
programmed one, writes DCSURF_SURFACE_PITCH/PITCH_C under the same lock
(DC's MED plane_size update; `write_fetch_pitch`), DML keeping the staged
pitch it admitted. A client framebuffer must lie in the frame-buffer
aperture, start 256-byte aligned, hold every fetched row at a pitch of
whole pixels no narrower than the staged one, and have a chroma plane
exactly when the plane is 4:2:0; otherwise the flip is refused before any
register changes and the display keeps scanning what it showed.
`SurfaceApplied::chroma` carries the chroma offset and pitch HUBP fetches
with (`SurfaceApplied::staged` / `at_staged` for the staged buffers); a
plane flipped to a client framebuffer keeps both staged buffers unfetched,
a flip back to its back buffer swaps them as before; a seamless plane
update keeps a kept plane's client framebuffer with its pitch (only the
same plane keeps a surface: another plane that lands on the pipe, a
recreated one taking the pipe a removed one held, gets a fresh surface
with its first frame however alike the old allocation is,
`otg::PlaneContent::moved_to` from `planes::moved_planes` by DRM plane id,
so it never latches showing the other plane's image), and one that
puts a plane on fresh surfaces scans the commit's GEM framebuffer in place
from the update itself (`otg::PlaneContent::external` through
`boot::FirstFrames::external` and the platform's `CommitFrames`: the update
programs its address and pitches under the lock, copies no chunk, leaves the
fresh staged buffers cleared, and the pin joins the display's), as DC
programs a new plane's address in the update that adds it; a restage
returns to the staged buffers. `scanout_framebuffer` has no CPU view of a
client framebuffer, so the console leaves a display that scans one
(`follow_flip`). Unpinning is amdgpu_dm_plane_helper_cleanup_fb after the
flip that replaced it: the display's `PresentSlot` keeps every pin it may
fetch (taken before the flip or plane update that programs the address, so
one that fails after programming it leaves the buffer pinned) and `retire_scanout_pins` drops one only when
`ColdBoot::display_fetched_addresses` (`Otg::fetched_addresses`: each
plane's latched address while scanning out, none at rest, unknown while a
change is in flight or after a failure) shows no plane fetching it (after
each presenter flip, `flip_display`, and every display-monitor pass).
`release_client_scanout` implements the lastclose restore: every plane still
fetching a client framebuffer flips back to its back buffer and the pins
retire after the last card close (a failed release keeps the pins until a
later pass retires them: drm_fb_helper_lastclose ignores its restore error).
Suspend instead stops the streams through their retained teardown journal,
then retires pins; it never exposes an old or cleared staged buffer on the way
into S3. A cursor plane's GEM framebuffer is pinned in VRAM by the
commit's prepare and handed to the display's cursor task
(`amdgpu_navi48_platform::CursorContent::Gem`, `GemCursor`), which waits
for the buffer's WRITE fences (the plane fence drm_gem_plane_helper_prepare_fb
takes and drm_atomic_helper_wait_for_fences waits for; NARF bounds the
wait at 10 s, Linux does not) before it copies the rows for the hardware
cursor (`GemPlacement::read_bytes`) and shows them at the commit's
position; the cursor keeps its previous image and position until then,
and a newer commit supersedes a pending one. A dumb cursor's rows are
copied at the commit. Dumb buffers are such GEM buffers in VRAM (below) and take
this path; only one of the card's own system-memory dumb buffers, made
while no VRAM heap was up, is still CPU-copied.

**Dumb buffers in VRAM.** On the native card, once its client VRAM heap is
registered (`drm_ioctl_bridge::amdgpu_vram_dumb`), `DriCardFile` answers
CREATE_DUMB as amdgpu_mode_dumb_create (`drm_ioctl_bridge::amdgpu_dumb`,
`GemState::create_dumb`): drm_mode_create_dumb's checks, the pitch of
`amdgpu_gem::align_pitch` and the page-rounded size (`dumb_layout`), in
`DUMB_DOMAIN` (amdgpu_display_supported_domains on a dGPU without
gpu_vm_support: VRAM) with `DUMB_CREATE_FLAGS` (CPU_ACCESS_REQUIRED |
CPU_GTT_USWC | VRAM_CONTIGUOUS | VRAM_CLEARED). The buffer is one zeroed
reservation in the BAR-visible heap and its handle is in the open's own
GEM table (Linux's per-file handle space; the card's dumb table holds
none). It is stored as amdgpu_bo_create leaves it: VRAM_WIPE_ON_RELEASE
added, the CPU_ACCESS_REQUIRED hint dropped, alignment 0 (GEM_OP), allowed
domains VRAM | GTT. Full visible VRAM first evicts idle unmapped buffers
(`evict_visible_locked`), and from a user open (`amdgpu_create_dumb_async`,
`amdgpu_gem::create_dumb_async`) mapped ones too (`reclaim_vram_locked`, shared
with GEM_CREATE's strict path); there is no GTT fallback, so it is then
ENOMEM. MAP_DUMB and DESTROY_DUMB of one of an open's amdgpu GEM handles,
on any amdgpu card, are amdgpu_mode_dumb_mmap (`GemState::map_dumb`: the
GEM_MMAP offset, EPERM for a userptr or NO_CPU_ACCESS buffer) and
drm_gem_handle_delete (`destroy_dumb`); other handles fall through to the
card's table. mmap of the offset is the revocable CPU-mapping backing
(`cpu_mapping::backing`) over the buffer's BAR window, which follows the
buffer when it moves. ADDFB2 of the handle is `amdgpu_addfb2_bo`, so
showing it pins it and scans it out in place as above. Native amdgpu user
KMS requests go through `drm_ioctl_bridge::amdgpu_kms_async`: SETCRTC,
PAGE_FLIP, SETPLANE, ATOMIC, SETPROPERTY/OBJ_SETPROPERTY and CURSOR/CURSOR2.
The bridge checks DRM master before any guarded user copy, then copies the
supported request once into owned storage before awaiting. ATOMIC retains
the existing bounds (256 objects, 4096 properties) and guarded copies every
nested array. Target resolution and commit use that same snapshot; no
request header, property array, connector id or cursor handle is reread
after migration. TEST_ONLY neither acquires placement admission nor migrates.
SETCRTC/PAGE_FLIP/SETPLANE prepare only their named enabled framebuffer;
atomic and plane-property requests prepare each touched plane's final
enabled framebuffer after inheriting its current FB_ID/CRTC_ID. Disables
prepare nothing. Framebuffer lookup is global, as the commit's lookup is:
another open's framebuffer and a legacy cursor's internal framebuffer are
valid targets for the current master; their owning open controls cleanup.
A legacy cursor BO update captures only its own open's handle through
`GemState::object_unvalidated` (no opportunistic promotion), while a
MOVE-only request inherits the cursor plane's current framebuffer.

Placement admission precedes the inherited-state snapshot, then the KMS
spinlock is released before any wait or migration. Before migration, the
owned request passes the commit's ordinary checks: atomic/property requests
use a TEST_ONLY view, SETCRTC/PAGE_FLIP/SETPLANE stop at their existing pin
boundary, and cursor requests validate own-open source/shape and native
cursor checks. Invalid properties, objects, handles, geometry or flags do
not move a valid BO or reclaim another. SETCRTC preserves the bridge's current
behavior of presenting any nonzero fb_id even with mode_valid zero; SETPLANE
disables only for fb_id zero. A nonzero FB with an absent CRTC is refused.
Targets outside VRAM move
through `amdgpu_vm::relocate`, with CPU mappings following. If necessary,
`reclaim_vram_locked` evicts idle BOs under the same borrowed placement guard,
excluding the complete target set (including BOs already promoted by this
request), pinned scanout and busy jobs. Failure propagates before any KMS
state, event or pin handoff changes. The actual commit rechecks current DRM
master and every target's framebuffer id/BO identity under the Card lock;
changed inherited state or identity is Busy, revoked master PermissionDenied.
The guard remains through `PreparedFbs` pinning, including already-resident
BOs, and releases on success, error or cancellation. Hotplug reuses the
presenter's already-pinned `PlaneFrame`; it does not promote an open's idle
framebuffers. Legacy CURSOR/CURSOR2 with one of the open's GEM handles wraps that
buffer (`drm_ioctl_bridge::amdgpu_cursor_bo`, `Card::addfb2_bo` with no
owning open, so drm_fb_release leaves it). Deviations: a System RAM/GTT placement remains write-back to preserve the
direct-map alias (NARF does not retag RAM as USWC). User VRAM mappings are
write-combined through the typed mmap backing. Migration back to VRAM runs before the commit
rather than inside the pin;
DRM_MODE_CREATE_DUMB from the render node keeps the card's table.
SETCRTC admits such a framebuffer as a placed primary
(`drm_native_planes::setcrtc_planes`), PAGE_FLIP requests the display's
planes so a tiling change is a plane update.

**Plane input color.** amdgpu_dm exposes no plane color property on DCN
4.0.1 by default: the plane DEGAMMA/HDR multiplier/CTM/shaper/3D/blend LUT
properties are AMD_PRIVATE_COLOR only, and the COLOR_PIPELINE (drm_colorop)
property only reaches clients with DRM_CLIENT_CAP_PLANE_COLOR_PIPELINE,
which NARF does not implement. amdgpu_dm_update_plane_color_mgmt then
bypasses the input transfer function unless the CRTC's legacy (256-entry)
gamma sets cm_is_degamma_srgb, when map_crtc_degamma_to_dc_plane gives each
plane a predefined degamma by format (`otg::InputTf::implicit`): BT.709
for NV12 (DC's VIDEO_420_YCrCb; "no transfer function for BT601"), sRGB for
RGB and P010 (VIDEO_420_10bpc_YCrCb is not in its switch). sRGB stays
TF_TYPE_PREDEFINED, which dcn32_set_input_transfer_func hands to
dpp3_set_pre_degam (PRE_DEGAM mode 1, select 0) with the GAMCOR bypassed;
BT.709 is not a ROM mod_color_calculate_degamma_params keeps on DCN 4.0.1,
so it becomes TF_TYPE_DISTRIBUTED_POINTS (build_degamma's inverse BT.709
OETF from 2^-12 to 2^0, clamped: `amdgpu_dcn_color::bt709_degamma_tf`),
PRE_DEGAM is bypassed (UNITY) and dpp3_program_gamcor_lut loads
cm3_helper_translate_curve_to_degamma_hw_format's 256-point PWL
(`amdgpu_dcn_color::translate_curve_to_degamma_hw_format`,
`otg::bt709_degamma`, computed once) into the CM_GAMCOR RAM not in use
(B from bypass or A, A from B: power on, MODE 2, host select, the RAM's
control words, the LUT with its last value repeated, then SELECT). The
choice is `InputTf::pre_degam` and `PipeColor::{pre_degam, gamcor}`,
programmed per fetching DPP by `Engine::input_tf` and
`Engine::program_input_tf`; staging and the verifiers follow that record
(CM_GAMCOR_CONTROL MODE/SELECT included). Every DPP setup also programs the
cursor matrix as dcn401's hwseq does after dpp_setup:
dpp401_set_cursor_matrix forces COLOR_SPACE_UNKNOWN, so CUR0_MATRIX_MODE is
bypass over RGB and YCbCr planes alike (`dpp::CURSOR_MATRIX_WORD`). The
cursor's attributes carry amdgpu_dm's ENABLE_CURSOR_DEGAMMA under legacy
gamma (DCN401's dpp gamma_corr cap), which dpp401_set_cursor_attributes
makes CUR0_ROM_EN for the premultiplied cursor
(`CursorApplied::degamma`, from the CRTC with every attribute update, a
move included; a changed CRTC color on a live display reprograms the
cursor's attributes and position too (`Surfaces::set_color`, under
`Otg::set_color`), as amdgpu_dm_atomic_check adds the CRTC's cursor plane
to a commit whose color_mgmt_changed).

Gaps: planes on an ODM stream
must reach every segment; no
RGBA8888 planes (Linux's native setup refuses them), no NV21 (not
on DCN4's universal planes), no COLOR_PIPELINE plane color (nor Linux's
AMD_PRIVATE_COLOR properties); DML admits a client framebuffer at the
staged (minimum) pitch; a linear RGB GEM framebuffer whose source rectangle
starts off a 256-byte boundary is not shown (DC offsets the viewport); the
cursor image is still copied out of its buffer; offered alternative modes are admitted without the
display's overlays, and KMS admits planes only on the lit timing (a mode
switch with overlays relights and falls back if they no longer fit).
OBJ_SETPROPERTY (and the connector-only SETPROPERTY) on any connector,
CRTC or plane of an atomic card is set_property_atomic
(`drm_ioctl_bridge::set_property_atomic`): a blocking one-property commit
with modesets allowed (drm_atomic_commit_init sets allow_modeset) and no
event, through the atomic decode/check/commit
(`drm_ioctl_bridge::atomic_commit`, shared with DRM_IOCTL_MODE_ATOMIC), so
every atomic property an object carries is settable (CRTC ACTIVE/MODE_ID,
connector CRTC_ID, a CRTC's OUT_FENCE_PTR, which gets -1 and no fence);
out-of-range, immutable or absent properties are EINVAL and an object not
of the given type ENOENT. Non-atomic cards keep set_property_legacy. Model-tested only
(`dcn401-spl`, `dcn401-dml`, `dcn401-dpp`, `dcn401-mpc`, `dcn401-requestor`,
`dcn401-deadline`, `dcn401-scanout`, `navi48-modeset`, `navi48-kms`, `drm`,
`drm_ioctl`); not validated on hardware.

### Navi 48 seamless shared-clock changes

A configuration change that keeps running displays lit follows
dc_commit_state_no_check's prepare/optimize ordering with dcn401's clock
sequence. Every change starts pinned (`ColdBoot::pin_display_uclk`, before
its first clock or watermark change; see "Navi 48 UCLK P-state switching"
for the entry points); switching is regained only by the display monitor's
P-state step.

`ColdBoot::modeset_beside(fill, want, crtc_of, mst: &[MstRoute])` lights
new board sinks and new MST end devices beside the running displays (route
CRTCs already lit are ignored), returning
`Result<Configuration, BesideRefusal>` within its error: DML admits every
running display's mode with as many new ones as fit (`dml::admit_native`,
CRTC order), each running display keeping its pipes (`modeset::keeps_pipes`:
the same mode, ODM segments and MPC slices; otherwise
`BesideRefusal::Other`, as for no free slot or a running configuration that
no longer fits, before any change). A new end
device is selected beside its port's running streams
(`mst::select_mst_outputs_beside`): without DSC decoders a running payload
stays as it is (Linux runs drm_dp_atomic_find_time_slots only for changed
connectors) and the new stream takes the slots, hop PBN and payload count
(`MAX_PAYLOADS`) it leaves; with decoders the link's fairness search reruns
over the link's streams in topology order, each running one at its place
with its timing and depth and each new one through the depth loop
(is_dsc_need_re_compute, compute_mst_dsc_configs_for_link), and a change
to (or a search that no longer fits) any running stream's PBN, slots or DSC
returns `BesideRefusal::DscFairness`; Linux modesets those streams
(drm_dp_mst_add_affected_dsc_crtcs; pre_validate_dsc keeps the rest), and
so does the platform below. Documented deviation: amdgpu_dm searches in
dc_state order (the order the streams were added); NARF searches in
topology order, which the affected-stream search below shares, so that a
partial relight lights the affected streams back with the configuration
that search found and keeps the others (with the running streams first,
some topologies refused that relight every time and fell back to a full
one). `BesideRefusal::Other` for an MST session with an uncertain
transaction or a dirty topology under streams, or a root whose rescanned
link caps no longer match the running streams'. The new stream lights as in a
full configuration (`start_mst_stream`): on a link that runs it attaches and
adds only its own payload — payload-table row, SAT rows for every stream
with ACT, ACT handled, ALLOCATE_PAYLOAD for its VCPI, its VC rate — while
the other streams' timing, OPTC, VTG, DIG and VC rate are not written; on a
port with no stream it trains that port's link. Then:
prepare_bandwidth — `update_live_display_clocks(request, targets, false)`
(the clock owner's `update_live` with every display's registers held, the
running pipes' DPP DTOs raised where needed, every DCCG record and every
display's timing records rebound, `Otg::rebind_clock`), and each running
display moved to its new plan with raise-only watermarks
(`update_live_display_plan(pipe, plan, true)`: `Otg::update_live_plan`
writes optc1_program_global_sync, the VTG's VSTARTUP point, every HUBP's
DLG/TTU and the DCHUBBUB watermarks (`WatermarkUpdate::Raise`) and arbiter
under the OTG master lock, waits for the latch and rebinds every record of
the timing, `Status::rebind_timing`); the new displays' pipe clocks beside
the running ones (`prepare_display_pipe_clocks_beside`) and their usual
lighting; optimize_bandwidth — each running display's exact watermarks,
then `update_live_display_clocks(request, all targets, true)` lowering what
the configuration no longer needs. `replan_displays()` does the same for the
displays left after one leaves, MST streams included (their payloads and
links untouched; a departed MST stream's own teardown removed its payload:
VC rate zero, ALLOCATE_PAYLOAD with PBN 0, its payload-table row cleared, SAT
without it with ACT, later payloads compacted). The platform monitor lights
a new sink or end device beside the running displays when nothing they
asked for changed (`MonitorStep::LitBeside`) and replans after a display
left (`MonitorStep::Replanned`), relighting everything only when refused.

`ColdBoot::mst_affected_streams(port, joining, want) -> Option<u8>` (by
CRTC; `mst::affected_mst_streams`) gives the running streams on `port` a
commit must modeset, as amdgpu_dm finds them: every stream of the topology
in the commit (drm_dp_mst_add_affected_dsc_crtcs), the link's fairness
search run over them all with the devices `joining` lights in topology
order (each running stream at its timing, through the depth loop), and
every stream whose
timing, depth, DSC (dc_is_timing_changed) or payload that changes kept in
the commit, the others not (pre_validate_dsc). A link without decoders
never modesets running streams. The monitor uses it both ways
(`MonitorStep::Reconfigured`): when a beside lighting is refused for DSC
fairness (`BesideRefusal::DscFairness`; any other refusal relights
everything), the running streams the new end devices change are torn down
and lit again,
with them, beside the displays left running; after an MST stream left, the
streams its departure changes are torn down and lit again beside the
others. Only a search that fits nothing relights everything.

A board HPD rising on a port with no display lit (`hpd_rise`) lights only
the new connector: an SST sink, or a branch whose session starts there
(`start_display_mst` after DPCD MSTM_CAP, its end devices' connectors added
and the root's emptied, as a lighting starts it) and whose devices then
light beside the running displays, the new port's link trained on its own.
A rising HPD on a port whose display runs (its sink replaced without HPD
seen low) still relights. The board sinks are probed beside the running
displays even when the plugged port's CRTC is off (`light_beside`'s
`reprobe`), refreshing its connector.

Gaps: mode or color changes of a running display and FRL retraining still
relight (plane changes no longer do: see below); a lost hop capacity or a
changed primary branch on an MST link still relights; a running display
whose new plan needs other pipes refuses the seamless change; scanning for
the new sinks reads every port (AUX/DDC) while the others run; an affected
MST stream lit again is selected beside the unaffected ones (seeded
search), so a search whose result depends on the order falls back to a
relight. Model-tested only (`dcn401-clk`, `dcn401-dccg`,
`dcn401-scanout`, `navi48-modeset`); not validated on hardware.

### Navi 48 seamless plane updates

A plane change (placement, scaling, blending, rotation, format, tiling,
surface, an overlay added or removed, the primary's format) is no modeset
in amdgpu_dm (amdgpu_dm_commit_planes through dc_update_planes_and_stream),
and none here: the display keeps scanning out, its OTG, OPP, DSC and link
untouched.

**Classification.** `otg::plane_update_type(old, new) -> UpdateType`
(`Fast`, `Med`, `Full`) is det_surface_update for a plane DC keeps:
get_plane_info_update_type (color space, per-pixel or global alpha and the
pitch medium; rotation, DC format (X/A twins are one), bytes per pixel,
tiling and DCC full) and get_scaling_info_update_type (a source or
destination of another size full, one moved medium). A plane whose MPC split
changes (`SurfaceRequest::mpc`: DML combining it on another DPP, no longer,
or on another pipe) is full, whatever its surface: dc only re-splits pipes in
a full update's validation. The pipes such a change takes or frees follow
the rules below (full; another display's pipes or another ODM split
relight).
`planes_update_type(old, new, reset)` is check_update_surfaces_for_stream
over the stream's planes: a plane count change (full_update_required_weak)
or a plane amdgpu_dm recreates (`reset`, should_reset_plane on a zpos
change: an overlay both setups show moved across the primary or past
another) is full. An update that takes or frees pipes is full.

**Engine.** `unsafe Otg::update_live_planes(pool, clocks, dccg, gmc, pipe,
&LivePlanes { primary, overlays, reset }, plan, crystal_khz, content: &mut
dyn PlaneContent) -> PlanesUpdated` (ColdBoot `update_live_display_planes`,
same `content`) moves display
`pipe`'s live scanout to the surface requests (the primary on its own pipe
and ODM pipes, MPC slices free to change; overlays bottom first on pipes of
their own) under `plan`, its stream's own timing admitted with them, in
commit_planes_for_stream's order:
- Checks, before any write: the display scans out, every request stages
  (SPL), sits on the stream split like it and on pipes no other plane or
  display holds, underlays below the others, and
  the plan binds the new planes and the current owners
  (`deadline::bound`), the live scanout is still the one its records name
  (`scanout_bound_with`, raise-tolerant watermarks), no flip is pending,
  and every pipe a new plane takes is free (its OTG idle and unlocked, its
  MPCC in no tree and idle, and powered, its HUBP blank, drained and gated,
  its DPP stopped). Every further pipe's DPP-only clock must cover its
  plane's DPPCLK. A plane of the same allocation on the same pipes keeps
  its surface (and content); any other takes a fresh, cleared one
  (unpublished until the hardware hears of it) holding its first content:
  `PlaneContent::chunk(a, index, words) -> Option<u64>` hands chunk `index`
  of surface `a`'s bytes and its offset (`otg::Cleared` hands none), written
  before the update's first register write, so the VUPDATE that latches the
  new plane already shows its framebuffer, as DC scans a new plane's address
  from the update that adds it. A chunk outside the surface refuses the
  update (no register written).
- Before the lock (dcn20_enable_plane): each new pipe powered up if gated
  (dcn32_hubp_pg_control), its fetch clock, the VMID0 aperture, the
  requestor on the stream's VTG and the DPP clock; compbuf is reduced before
  any planned DET grows.
- Under dcn401_interdependent_update_lock (the OTG master lock): the global
  sync if the plan's differs; for every freed pipe its DET released
  (`Engine::program_det_segments(q, 0)`, dcn401_program_det_segments, no
  wait) and then its plane_atomic_disconnect (mpc1_remove_mpcc) with its
  cursor off, as dcn401_program_front_end_for_ctx orders them; the retained
  and new planes receive their plan's DET (reductions before increases), then
  each changed or new plane's DPP
  (dpp401_dpp_setup and the DSCL with the coefficient RAM swap,
  `program_dpp_live`); on a full update every segment's MPCC tree from its
  top pipe down as dcn20_update_mpcc does (each MPCC removed, inserted at
  the bottom with mpc1_insert_plane, then its blending), on a medium one
  only the changed planes' blending (update_blending); each changed or new
  plane's HUBP surface, viewport and address; every plane's DLG/TTU with
  raise-only watermarks; the CRTC color on the new top MPCCs
  (program_color); the cursor on every pipe it now overlaps; the new pipes
  unblanked.
- Unlocked (dcn401_post_unlock_program_front_end): every plane's HUBP
  reports its surface in use, the OTG's double-buffered state latched, the
  new MPCCs connected and the freed ones idle; then dcn20_disable_plane on
  each freed pipe (no outstanding request, blank, fetch and DPP clocks
  off), and then on every update optimize_bandwidth's compbuf increase
  (`Engine::increase_compbuf`, dcn401_program_compbuf_segments with
  safe_to_increase: when COMPBUF must grow to the CRB's remaining segments
  (CRB minus every requested DET, independent of the default DET size),
  every DET_SIZE_CURRENT is waited for as Linux's REG_WAIT(…, 1, 100),
  about 100 µs each, then COMPBUF grows; with no grow nothing is waited
  for; the requestor record carries it). A slow acknowledgement is logged,
  never fatal, as REG_WAIT only logs: after a slow DET the grow is deferred
  and the requested allocation kept (deviation: Linux writes COMPBUF_SIZE
  anyway, an overlap its own ASSERT calls an erroneous configuration; NARF
  never grows into segments a DET may still hold). The deferred grow stays
  pending (`Otg::compbuf_pending`) and is retried on the next optimize pass
  (`Otg::retry_compbuf` from `ColdBoot::retry_display_compbuf`, run by
  every monitor pass's `converge_uclk_pstate`; a hub mid-transaction is
  tried on the next pass), every display's requestor record then carrying
  the grown size. A grown compbuf whose CURRENT is slow is kept (Linux does
  not wait for it). The records
  then name the new planes (surfaces, apertures, DPP/MPC, requestor,
  deadlines, scanout, cursor, the timing's sync) and pass the scanout's
  re-binding checks; the surfaces the update superseded (with their back
  buffers; the primary's cursor image moves with its slot) are released once
  nothing fetches them, after an HDP flush.

Refusals leave the scanout as it ran; later failure or cancellation
(`State::UpdatingPlanes`) quarantines the display, retaining every surface.
`PlanesUpdated` reports the update type, the pipes enabled, disabled and
kept, the scanout (its plan the deadlines') and the bytes released (boxed).
`ColdBoot::prepare_display_plane_clock_live(request)` programs a new
pipe's DPP-only clock while every display (the selected one's too) runs.

**Configuration.** `unsafe ColdBoot::update_display_planes(display,
format, setup, reset, frames: &mut dyn FirstFrames) -> Option<PlanesChange>`
(`PlanesChange { pipe, displays, updated }`; `FirstFrames::chunk(slot, a,
index, words)` is `PlaneContent` by plane slot, 0 the primary and k + 1
the setup's overlay k) admits every running display again with the
display's new planes (`dml::admit_native`), places them as DC acquires
them on the running state (`modeset::live_pipes` with `planes_reset`, see
"Pipe acquisition": recreated planes take their blending tree's pipes back
top first, new ones pipes the running state leaves free, a plane only moved
keeps its pipes), then: prepare_bandwidth (`pin_display_uclk` first, as
dcn401_prepare_bandwidth forces UCLK P-state support off before
update_clocks, then `update_live_display_clocks` raising the shared
clocks and the DTOs of the pipes that keep fetching, the new pipes'
DPP-only clocks, every other display whose plan moved through
`update_live_display_plan(raise)`), the plane update, optimize_bandwidth
(every display's exact watermarks, the clocks lowered). `None`, before any
change but the pin and the clock raise, when it needs a modeset or is refused: an MST
configuration, a teardown in flight, DML refusing the configuration, another
ODM split for the display, another display's pipes or split changing, a
request that does not stage, or the engine's refusal.

Live DET changes settle active CURRENT fields after VUPDATE before publishing
the new plan. An idle zero request is deferred only when the driver retained
ownership of that retirement; an unrelated release must acknowledge CURRENT
before its space can fund growth. Cold allocation adoption remains strict.
Live checks count requested and current capacity conservatively and permit
only owned idle retirements or safe compbuf growth in flight. Compbuf capacity
needed by a plan must acknowledge before publication; growth beyond its
minimum may remain deferred. Across streams, net DET releases complete before
budget takers, including a plane removal that frees space for a sibling.

**Platform and KMS.** `request_display_planes` and `request_display_format`
wake the display monitor (it sleeps in 16 ms steps), which applies a plane
or format change of a display that otherwise runs on through
`update_display_planes` (`MonitorStep::PlanesUpdated`, not logged),
withdrawing the console from the display's primary across it, then
publishes the display's new planes to its presenter (back buffers for new
overlay pipes, the planes and format shown, the CRTC's admission); it
relights only when that returns `None` or a modeset is due anyway. A frame
of a commit whose planes are not shown yet waits in the mailbox for the
update (at most 2 s, then presents on what is shown), so a commit's new
planes and framebuffers show from the same update: the update takes the
waiting frame as the first content of every plane it puts on a fresh
surface (`CommitFrames`, each plane copied as the presenter copies it when
it is in the format and tiling the plane is shown in), and the presenter
then flips that frame, completing its event. `drm_native_planes`
records each overlay's DRM plane id in `OverlayPlane::plane`.

Gaps: a plane that keeps its surface shows a commit's new framebuffer from
the presenter's flip after the update latched, not at the update's own
VUPDATE, and the commit's flip event completes with that flip; a frame
queued after the update copied the planes shows from that flip too; a
change of the stream's ODM split (or another display's pipes) still
relights; MST displays relight; MALL/SubVP reprogramming remains absent. The cursor matrix stays bypassed over
YCbCr planes as dcn401 leaves it (dpp401_set_cursor_matrix), its degamma ROM
following legacy gamma ("Plane input color"). DRM cursor planes are
described in "Navi 48 DRM cursor planes".
Model-tested only (`dcn401-plane-update`, `dcn401-cursor`,
`dcn401-scanout`, `navi48-modeset`, `navi48-kms`); not validated on
hardware.

### Navi 48 DRM cursor planes

The native card gives every CRTC amdgpu_dm's DRM_PLANE_TYPE_CURSOR plane
(amdgpu_dm_crtc_init, amdgpu_dm_plane_init with no plane caps):
`drm_native_planes::planes_for` appends one per CRTC after the primaries and
overlays (`CURSOR_PLANE_ID_BASE` 0x47 + CRTC index, `NativePlane::cursor_of`
naming its CRTC; `NativePlane::is_overlay`/`is_cursor`; `cursor_ids`,
`cursor_of`). GETPLANERESOURCES lists them last; GETPLANE reports
possible_crtcs of its own CRTC only (drm_crtc_init_with_planes) and
`CURSOR_FORMATS` (ARGB8888); OBJ_GETPROPERTIES reports type Cursor (2), the
core plane properties, its own "pixel blend mode" (`CURSOR_BLEND_PROP_ID`,
Pre-multiplied only: DC blends the cursor pre-multiplied) and immutable
"zpos" 255 (`CURSOR_ZPOS_PROP_ID`), then IN_FORMATS and IN_FORMATS_ASYNC:
ARGB8888 under DRM_FORMAT_MOD_LINEAR alone
(amdgpu_dm_plane_get_plane_modifiers for a cursor). It has no rotation,
alpha, color or HOTSPOT_X/Y properties (amdgpu is not
DRIVER_CURSOR_HOTSPOT), and DRM_CAP_CURSOR_WIDTH/HEIGHT stay 64.

Checks (`drm_native_planes::check`, so ATOMIC with TEST_ONLY, plane
OBJ_SETPROPERTY, SETPLANE and the legacy ioctls alike), each EINVAL:
drm_atomic_plane_check's possible_crtcs and format/modifier (ARGB8888,
LINEAR); for an enabled cursor `check_cursor(CursorFb, src, crtc)`:
amdgpu_dm_check_native_cursor_state with dm_check_cursor_fb (SRC_X/Y 0, the
whole framebuffer as source, at most dc caps' max_cursor_size 64 square, a
pitch of exactly the width in 64, 128 or 256 pixels, linear) and
amdgpu_dm_atomic_check's DCN 4.x refusal of a scaled cursor (CRTC_W/H equal
to the source); a SRC_* fraction on an enabled cursor is refused at decode
(Linux compares the 16.16 values). The cursor's CRTC gets
dm_crtc_helper_atomic_check (an enabled CRTC needs its primary), but DC gets
no plane: amdgpu_dm_crtc_get_cursor_mode is always native on DCN 4.0.1, so
a cursor commit is a FAST update and relights nothing. Negative CRTC_X/Y are
taken; the hardware moves them into the hotspot
(amdgpu_dm_plane_get_cursor_position).

Commit: `drm_native_planes::cursor_changes(card, state)` (before the commit)
gives handle_cursor_update's input per cursor plane (the CRTC, the
framebuffer or off, CRTC_X/Y, a legacy-wrapped framebuffer it lets go of);
the bridge reads the framebuffer's rows out of its dumb BO
(`drm_native_planes::cursor_image`) and sends
`amdgpu_native_kms::request_display_cursor(display, image, position)` after
the card lock drops. Cursor planes never present frames, set the display's
format or reserve hardware flip tickets; a cursor-only commit's event is
software-paced. `platform::request_display_cursor` records the plane per
display (`CursorImage`, premultiplied ARGB8888) and a task converges the
pipe's hardware cursor under OWNER (`drm_cursor_step`: an image the pipe does
not hold is uploaded with `set_display_cursor`, the one it holds is moved,
an off plane hides it with an off-screen move); every monitor pass converges
again, so a relit display gets its cursor back (amdgpu_dm commits cursors
after the planes). While DRM drives a display's cursor the console's cursor
hook leaves it alone; the last DRM file closing (`restore_displays`) turns
DRM's cursors off and the console uploads its pointer again. RMFB of a
cursor's framebuffer turns the cursor off.

Legacy CURSOR/CURSOR2 on a card with native planes are
drm_mode_cursor_common and drm_mode_cursor_universal: DRM_MASTER (EACCES),
flags none or unknown EINVAL, an unknown CRTC ENOENT; DRM_MODE_CURSOR_BO
wraps the BO in an internal framebuffer (drm_internal_framebuffer_create:
ARGB8888, pitch width * 4, ENOENT for an unknown handle, amdgpu's
framebuffer checks) or, with handle 0, turns the cursor off; without BO the
plane keeps its framebuffer; without DRM_MODE_CURSOR_MOVE the position is the
CRTC's last legacy one (`NativePlane::legacy_position`, updated only by a
successful MOVE). The update then runs the cursor plane's checks and commit
(`__setplane_atomic`); a refused update drops the wrapped framebuffer, and
the plane's previous wrapped framebuffer (`NativePlane::internal_fb`) goes
when it takes another. CURSOR2's hotspot is dropped, as Linux does for a
driver without DRIVER_CURSOR_HOTSPOT. SETPLANE of a cursor plane takes the
same path. Cards without native planes keep the fb pointer path.

Gaps and deviations from Linux: the hardware cursor scans a copy of the
framebuffer taken at the commit (Linux scans the pinned BO), so drawing into
a shown cursor BO without a new commit is not seen; a framebuffer without a
dumb BO turns the cursor off; a wrapped framebuffer is listed by
GETRESOURCES and removable by id like a client's (Linux keeps it off the
file's list); OBJ_GETPROPERTIES lists IN_FORMATS after the blend mode and
zpos, as on the other native planes (Linux attaches it first); cursor
updates are not tear-free (one cursor buffer per pipe). Model-tested only
(`drivers/gpu/drm`, `drivers/gpu/drm_ioctl`, `navi48-kms`); not validated on
hardware.

### Navi 48 UCLK P-state switching

`amdgpu_dcn401_dml::pstate::admit(&Soc, &UclkLevels, &[Mode], fams2) ->
Result<Pstate, Error>` is DML21's `dml2_top_soc15_build_mode_programming`
from the latency phase on, with DCN401's PMO left on, over the board's whole
UCLK DPM table (`UclkLevels`: one to eight ascending levels, the last the
pinned `Soc::uclk_khz`). The configuration must first admit natively
(`admit_native`). `dml2_mcg_dcn4`'s fine-grained min-clock table gives each
level its DRAM bandwidth and the FCLK/DCFCLK DML assumes (every level above
the first at least the balanced fabric clock of the level below, clamped,
pruned past the DCFCLK/FCLK maxima and de-duplicated). Mode support runs at
the lowest entry, else the highest and phase 1's binary search; at an entry
above the first the per-UCLK QoS row is variant A's empty second row, so the
maximum urgent latency loses its UCLK term, as in Linux.

The UCLK P-state phase is `dml2_pmo_dcn4_fams2.c`: DC's options for DCN401
(`dml21_populate_pmo_options` with the debug defaults: vblank on; SubVP,
clamped and variable DRR and FAMS2 on only with `fams2`, i.e. DMUB firmware
reporting FAMS 2.1; even-odd off), the base strategy lists expanded into
their permutations and DRR variants (`pstate::strategies(n)`), per-stream
P-state meta (vline time, scheduling/contention/interrupt/allow-to-target
lines, blackout, vactive fill delay and allow window, vblank window, SubVP
microschedule and phantom size, DRR stretch), vactive capability (margin at
least a quarter of the 400-us blackout), synchronized timing groups and
validate_pstate_support_strategy_cofunctionality with is_config_schedulable
(stages 1-4), the first ten candidates. Each candidate's overrides (vactive:
the excess fill bandwidth of the blackout's bytes over its fill delay, and
mode support requiring the vactive margin; vblank: 400 us reserved) are run
through mode support at the current latency index, which candidates allowing
it raise on failure; pmo_dcn4_fams2_test_for_pstate_support accepts the
first. The stutter phase then raises every plane to the 54-us reservation if
mode support still passes. DPMM maps the result: active minimums boosted to
the SVP-prefetch ones, idle minimums from the idle average derates, UCLK
rounded up to its DPM table, FCLK/DCFCLK fine-grained, FCLK P-state from the
planes' vactive hiding (clamped to the FCLK maximum when unsupported).

`Pstate::Supported` carries each stream's plan at the chosen latency level
(`Plan::pstate: Some(PlanPstate)` records the table, `fams2` and the
stream's `pstate::Method`; `Plan::readmits` repeats this search), the
methods, the level, the active and idle `MinClocks`, FCLK P-state support and
each stream's FAMS2 static base state (`Fams2Stream`, as
dml2_core_calcs_get_stream_fams2_programming fills it). The port programs
the hardware-exclusive methods only: `Pstate::Pinned(Pinned::Firmware(m))`
when Linux's search would reach a firmware method first (SubVP unless its
phantom planes or streams certainly do not fit; DRR never arises, every
native stream has `drr_config` disabled), `Pinned::Unsupported` when Linux
finds no strategy, and `Pinned::Port` for a DCC plane (MRQ meta rows) or a
DPMM clock above the latency state. Native admission (`admit_native`) is
unchanged and never carries a P-state record.

`pstate_strategies.txt` holds PMO's
expanded lists (`dcn401_pstate_strategy_lists_match_linux`).

The display owner applies the answer as dcn401_prepare/optimize_bandwidth.
`ColdBoot::start_display_clocks`, once the clock owner started, writes
`wm_range_table` to a 4-KiB VRAM range kept out of reuse, sends
`notify_wm_ranges` and runs `deep_sleep_control`. A table that cannot be
placed is skipped (as Linux skips a missing `wm_range_table`); firmware
refusals and ignored sent timeouts do not fail bring-up. An interrupted or
authority-failed watermark transaction retains an unusable clock owner,
which subsequent preparation refuses. Every refusal or error is logged in
`ColdBoot::display_power_policy()` (`DisplayPowerPolicy { wm_ranges,
deep_sleep }`). `ColdBoot::converge_uclk_pstate(drr)`, from every display monitor
pass before DRR converges, searches the running configuration (every
display scanning out without DRR, their plans one admission on the current
`Soc`, the clock owner's UCLK levels, `display_fams2()`); a configuration
found pinned is remembered and not searched again. Supported, in
dcn401_hwseq.c's order: prepare_bandwidth's
`update_live_display_bandwidth(bandwidth, false)` with `uclk_pstate` forced
false (Linux forces p_state_change_support false there, so clocks are only
raised and switching stays disallowed), every display moved to its P-state
plan with raise-only watermarks (`update_live_display_plan`), then FAMS2
disabled (`disable_display_fams2`: HW lock, the disabled FAMS2_CONFIG,
release; only with FAMS 2.1 firmware); then optimize_bandwidth's FAMS2
disabled again (no firmware method is required), the exact watermarks and
`update_live_display_bandwidth(bandwidth, true)` allowing switching with
UCLK/FCLK at DPMM's active and idle minimums; it returns the displays whose
plans moved. Otherwise, or with `drr` (a display that should run DRR: the
port plans DRR only pinned), `pin_display_uclk` (`bandwidth::pin_uclk`):
while `uclk_switching()`, UCLK and FCLK raised to their maxima with
switching disallowed and then FAMS2 disabled, as prepare_bandwidth orders
update_clocks before the FAMS2 update; nothing otherwise (Linux sends the
disabled FAMS2 config on every prepare_bandwidth; the port only ever sends
it disabled, so a pinned owner skips the repeat). Every configuration-change
entry point pins in prepare_bandwidth's position, before its first clock,
watermark, pipe or link change: `modeset_display`, `modeset_display_mode`,
`modeset_displays`, `modeset_routed`, `modeset_beside`, `replan_displays`,
`retrain_modeset`, `start_frl`, `retire_inherited_display`,
`modeset_mst_displays`, `add_display_mst_payload`, `update_display_planes`
(after its validation, before the shared clocks rise and the other
displays' plans move) and `update_live_display_planes`, and the teardowns
`stop_modeset`, `unplug_modeset`, `abort_modeset_activation` and
`remove_display_mst_payload`. `retrain_modeset` pins although Linux's
link-loss retraining (dp_handle_link_loss: dpms off, then on, on the
running state) takes no prepare_bandwidth, a conservative extra; on a
pinned or fresh owner that pin sends nothing. A teardown pins best-effort
(`pin_display_uclk_for_teardown`): Linux's prepare_bandwidth is void, so a
pin that fails (a failed clock owner) is logged and the stream is still
disabled; every other entry point returns the failure before any change.
`disable_display_fams2` never fails its caller either, as
dcn401_dmub_hw_control_lock and the FAMS2 update return nothing in Linux:
lock, disabled config and release are each tried (the release whatever the
update did) and a failure is logged. Flips, cursor, colour/HDR and DRR updates are
DC fast or stream updates, which Linux commits without prepare_bandwidth,
and do not pin (DRR is refused while switching). The step primitives those
entry points are built from (`start_display_scanout`, `stop_display_scanout`,
`update_live_display_plan`, `update_live_display_clocks`, the
`prepare_display_*` and `retire_display_*` steps, ...) do not pin by
themselves: a caller composing them must pin first. A P-state plan stays
valid pinned.
`deadline::bound` binds a pinned plan to the pinned UCLK floor with switching
disallowed and a P-state plan to a floor of at least its UCLK level; `set_display_drr`
refuses DRR while switching. `uclk_switching()` reports the policy.
`dcn401_scanout_chain_runs_a_uclk_pstate_plan` moves a live display to its
P-state plan and back on the harvested models; `dcn401-clk` and `dmub-navi48`
test the bandwidth sequence, the watermark table and the FAMS2 commands, and
`dcn401_fresh_display_owners_pin_like_linux_prepare_bandwidth` drives
`pin_uclk` over a real clock owner from the fresh states
`retire_inherited_display`, the first modeset and a relight after resume
start from.
Hardware switching under a lit display is unvalidated.

**No display left.** `converge_uclk_pstate` with no display and no
teardown in flight runs `ColdBoot::release_display_bandwidth` once: Linux
commits a context without streams (the last CRTC's disable, and dm_suspend's
commit before S3 or runtime suspend), whose dcn401_optimize_bandwidth runs
over dml21_init_min_clocks_for_dc_state's clocks. FAMS2 is disabled, then
`ClockManager::release(regs)` sends NumOfDisplays(0) (enter_display_off,
only when safe to lower), the DCFCLK hard minimum at its lowest level, the
deep-sleep DCFCLK zero, SetUclkPstateAllow(1) (total_plane_count == 0 sets
both P-state supports) and the active UCLK/FCLK floors at their lowest
levels with the idle ones zero, every result unread; every consumer must be
retired, and `Applied::request.displays` becomes 0. `uclk_switching()` then
reports true, so the next configuration change pins and its `prepare`
counts its displays and disallows switching again. After the bandwidth
sequence, DTBCLK, DISPCLK and DPPCLK hard minimums move to their first DPM
levels, in that order. Their requested minima and actual PMFW-returned rates
are retained separately; frequency responses and acknowledgements remain
required. Both runtime suspend and S3 retire all streams and run this release
before quiescing the device. dcn401_hardware_release
(FAMS2 off, P-state support forced on) is not ported: its only caller,
dc_hardware_release, has no caller in Linux (7.3), so Linux never runs it
before BACO or S3.

### Discrete RDNA2 PSP secure-OS bootstrap

`amdgpu_psp_boot::Firmware::open(gpu, registry_cap)` selects
the profile's SOS container for exact discrete RDNA2 PCI IDs. The required
GC/MP0 pairs are Navi21 10.3.0/11.0.7, Navi22 10.3.2/11.0.11,
Navi23 10.3.4/11.0.12 and Navi24 10.3.5/11.0.13, matching Linux's
`amdgpu_ucode_legacy_naming` and `psp_v11_0` backend. All use MP0 bank index 0
and the shared PSP11 bootloader protocol. Duplicate/missing IP instances and
undersized register banks reject
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

### Native Rust validation and fixture provenance

GPU tests exercise production Rust functions and retained owners directly.
Checked-in Linux/Mesa-derived vectors and reviewed hardware/codec tables are
regression data, with source hashes and upstream licenses preserved. No source
extraction, temporary Rust program, C/C++ shim or compiler comparison is part
of the GPU test gate. Internal models and static expected values do not
establish external source conformance, userspace compatibility or physical
GPU acceptance. See `../tests/README.md` for the data and validation boundaries.

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
as the Phoenix transport; every PSP11/13/14 ring is created with
`PSP_RING_TYPE__KM << 16` (`GFX_CTRL_CMD_ID_INIT_GPCOM_RING`, 0x00020000).
`setup_tmr_navi22(&amdgpu_psp_boot::Firmware).await` is `psp_tmr_init`: it
uses `Image::toc()` from the validated SOS container, submits `LOAD_TOC`, and
reserves the PSP-reported TMR size (nonzero, page-aligned, at most 64 MiB).
Containers without a TOC use PSP11's 4 MiB default. TMR allocations are aligned
to 1 MiB. MP0 11.0.11 has PMFW-centralized C-state management, so `SETUP_TMR`
(GPU and GPU-physical addresses, flags=2) is sent by `load_smc_navi22` right
after PMFW loads (`psp_hw_start`). Fence waits are bounded at 2 s
(`psp_cmd_submit_buf`); on Navi22 a nonzero response status is logged, not
fatal, except for `DESTROY_TMR`.
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

`Psp::load_smc_navi22(&Firmware).await` requires a Navi22 ring with `LOAD_TOC`
done and the TMR reserved but not yet set up. It stages only the microcode and
submits `LOAD_IP_FW` (6), firmware type SMU (18), using the GPU address and
exact payload length, then `SETUP_TMR`. Matching-fence
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
data revision 2.1 and FirmwareInfo 3.3/3.4/3.5 select the source: table ID zero
uses the VBIOS PowerPlay table, while a nonzero ID uses the SMC v2.0 container's
single embedded table or the v2.1 directory entry with that exact ID.
A missing or invalid selected source fails without
fallback. Supported Navy Flounder tables are exactly 2470 bytes, revision
16.0 / format `0x81`, with an 802-byte driver prefix and a 1668-byte SMC
payload. Accepted payload versions are 1 (firmware SKU) and 6 (observed on
MSI RX 6750 XT VBIOS `113-MSITV398MH.310`, PCI `1002:73df`, subsystem
`1462:3985` rev C0). Linux's `sienna_cichlid_store_powerplay_table` uses the
same `PPTable_t` layout for both. Preparation preserves the selected SKU's
version and policy; unknown versions and other wire layouts are refused.

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

### Shared discrete RDNA2 PSP ring, TMR and firmware upload

`unsafe amdgpu_psp_ring::Psp::new_rdna2(gpu, pci_cap, pool)` resolves the
exact PCI profile and requires matching GC, MP0, MP1 and SDMA identities.
The transport supports Linux's NBIO2.3 backend revisions and HDP5.0.x only;
missing/duplicate instance-zero records, absent base indices and out-of-bounds
register windows fail before allocation or device writes. GMC framebuffer
base/top/offset use `gc_10_3_0`'s offsets (0x16fc/0x16fd/0x16e7), not the
similarly named `gc_10_1_0` offsets. CP status uses GC bank index 0 and RLC
status uses index 1. Construction reads GMC under live PCI
authority, validates the CPU/GPU pool mappings, and reserves an unpublished
ring. The caller must exclusively own a physical GPU, with initialized VRAM,
permanent mappings and no concurrent PSP, reset or power-management users.

After `start().await`, `setup_tmr_rdna2(&sos).await` checks the SOS ASIC before
parsing or staging, submits its embedded TOC when present, and reserves TMR
without installing it. All four PSP11 revisions use Linux's centralized
C-state ordering. `load_smc_rdna2(&smc).await` requires the same ASIC, submits
only validated SMC microcode, then sends `SETUP_TMR`. SMC containers are
prepared by `amdgpu_smu_navi22::Firmware::open_rdna2(gpu, registry_cap)` through
live registry/blob invocations after exact GC/MP1 checks. The prepared
`profile()` is retained; no raw-byte constructor is exposed to callers.
This upload does not apply a board PPTable or issue SMU runtime/power commands.

`load_gfx_rdna2(&set).await` requires an ASIC-matching immutable prepared set
and completed SMC/TMR setup, then uses the shared graphics upload/autoload
state machine. `wait_gfx_boot_rdna2().await` observes idle CP and RLC boot
completion without GC writes. Completion does not initialize queues, memory
hubs, display or power policy, and does not advertise acceleration.
Sibling SOS/SMC/graphics sets fail before submission or allocation. Existing
Navi22/Phoenix/Navi48 entry points retain their separate target gates.
All shared-ring cancellation, bounded waits, capability checks and quarantine
rules apply. Verified `stop` still requires quiescing every TMR consumer first.
These explicit low-level APIs do not lift the native PCI probe gate.

### Navi 22 graphics firmware and PSP autoload

`amdgpu_gfx_navi22::Firmware::open_rdna2(gpu, registry_cap)` prepares an
ASIC-specific immutable set for any inventoried discrete RDNA2 PCI ID.
`Source::name_for(profile)` selects the containers. GC and MP1 must match the
profile's GC and PSP11 versions; SDMA0 must be 5.2.0/2/4/5 and DCN must be
3.0.0/0/2/3 for Navi21/22/23/24 respectively. VCN instance zero must be
3.0.0/64/192 for Navi21/22, 3.0.16 for Navi23 or 3.0.33 for Navi24. A bounded
instance mask rejects duplicate, missing-zero and out-of-range instances.
Preparation performs no device I/O and requires unique instance-zero discovery
records with valid bank bounds. The prepared set retains its `profile()`;
`load_gfx_navi22` refuses sets prepared for a sibling ASIC before submission.
These APIs do not enable native startup for newly inventoried PCI IDs.

`amdgpu_gfx_navi22::Firmware::open(gpu, registry_cap)` preserves the native
Navi22 gate and prepares the complete
`navy_flounder_{sdma,ce,pfp,me,mec,mec2,rlc,vcn,dmcub}.bin` set through live registry/blob
capabilities before any device I/O. Device gating requires PCI `1002:73df`,
GC 10.3.2, MP1 11.0.11, SDMA0 5.2.2 and DCN 3.0.0, with unique instance-zero
records, plus VCN instance 0 at 3.0.0/3.0.64/3.0.192 and an optional instance 1
(any VCN 3.0.x, 3.0.1 on Navy Flounder; Linux keys only on instance 0). Duplicate,
out-of-range or instance-1-only layouts are refused; VCN 3.0.16 uses different
firmware and is not Navy Flounder. `vcn_instances()` returns the instance mask
and `harvest_vcn(mask)` removes harvested instances before any device I/O
(`adev->vcn.harvest_config`).
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
VCN submits the complete common-header microcode payload once per unharvested
instance, as PSP type 13 (`UCODE_ID_VCN`) for instance 0 and 58
(`UCODE_ID_VCN1`) for instance 1 (`amdgpu_vcn_setup_ucode`); with both
harvested no VCN payload is sent. `Image::for_vcn_instances(mask)` selects them.
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
`media_firmware()` returns `MediaFirmware { vcn, dmcub, vcn1 }` GPU entry addresses
from completed PSP replies; each entry must be dword aligned and the full image
range must fit inside this session's retained TMR. On discrete RDNA2, DMCUB type 51 may instead
name the inherited secure instruction window CW0 inventoried before allocation,
or a new PSP-reported placement inside the owned VRAM pool. The latter is
claimed permanently in the pool before publication, and conflicts with any live
reservation fail closed; VCN remains TMR-only. The private inventory retains
the exact CW0/CW1 ranges, checks their GMC aperture against the PSP session and
permanently excludes them from both visible and above-BAR pools. Other
protected ranges do not authorize firmware, and disjoint reservations are never
widened into one range. Recovery carries the same inventory forward.
Partial failures retain any earlier valid address for
diagnostics. These are not CPU pointers or proof that the media engines have
started. Consumers must keep TMR alive. The API does not configure memory hubs,
queues, VCN/DMUB windows or board power, or set `AmdGpu::fw_loaded`.
Failure diagnostics identify an invalid ring write pointer and command,
graphics image preparation errors, the failed upload's source/type/length,
or a rejected media entry address together with the retained TMR bounds.
These messages run only on failure and preserve the existing validation and
ownership rules.

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

`unsafe amdgpu_gmc_navi22::Gmc::new_rdna2(gpu, pci_cap, pool)` shares the
GMC10 VMID0, GART and per-client GPUVM implementation across inventoried
Navi21/22/23/24 PCI IDs. It requires the profile's exact discovered GC version,
a supported MMHUB2.1.0/2.1.1/2.1.2 layout, NBIO2.3 backend registers and HDP5.0.x.
The MMHUB revision selects a compatible discovered backend rather than being
inferred from a marketed SKU. Linux `gmc_v10_0` selects `gfxhub_v2_1` for all
four GC versions and `mmhub_v2_0` for these MMHUB revisions. Both register
tables retain `gc_10_3_0_offset.h` and `mmhub_2_0_0_offset.h` as their
source provenance, including every base index. Native Rust tests exercise
the actual layout/admission paths; external hardware conformance is separate.
Missing/duplicate instance-zero blocks, absent base indices, unsupported
backends and truncated windows reject before allocating backing pages.

The constructor performs no I/O, leaves initialization explicit and inherits
the exclusive physical-device, trained VRAM, disabled gating, permanent pool,
queue/VM exclusion and memory-retention requirements below. Initialization
checks live PCI authority before touching device memory. Existing GART/GPUVM
methods keep the same ownership tokens, PTE/PDE validation, bounded engine-17
invalidation, fault handling and cancellation quarantine. This low-level API
does not enable native PCI startup or publish working acceleration for a new
card. `Gmc::new` retains its existing strict Navi22 gate.

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

### Navi 22 GART and per-client GPUVM

`Gmc::prepare_gart()` reserves the 1 MiB VRAM GART table plus one shared
all-invalid user root page (no I/O). `unsafe enable_gart().await` requires a
`Ready` hub owner and no running queues: it zeroes the table, carries the two
boot `Aperture` pages into GART pages 0/1, and repoints VMID0 on both hubs at a
512 MiB GART (`gmc_v10_0_mc_init` size) starting at the boot aperture, which
`Gmc::initialize` already placed at Linux's `amdgpu_gmc_gart_location`
BEST_FIT start (MC 0 below this board's 0x80_0000_0000 FB); the range may not
cross 4 GiB, overlap the FB or reach the MC hole. The FB end is
`fb_start + MEMSIZE`; `FB_LOCATION_TOP` is not consulted and an inherited
VMID0 context is reprogrammed (contexts 1–15 must be off). It then applies
`setup_vmid_config` to contexts 1–15 (`CONTEXT1_CNTL` 0x555407: depth 3, block
size 9, no retry, all default-page faults; table range 0..`max_pfn`-1) with
their base on the empty root, and invalidates VMID0. `gart()` returns
`GartInfo { start, size, table }` only after success.

`bind_gtt(DmaBuffer, writable).await -> Gtt` maps one pinned contiguous system
buffer (page aligned, below the 44-bit DMA mask) after the boot pages with
Linux TT flags VALID|SYSTEM|SNOOPED|EXECUTABLE|READABLE[|WRITEABLE], MTYPE_UC;
`Gtt::address()` is its VMID0 GPU address. `unbind_gtt(Gtt).await` writes
invalid entries, invalidates and returns the buffer. A dropped `Gtt` or a
failed unbind leaks the pages deliberately.

`allocate_vram(size, read_only) -> Buffer` returns zeroed pool VRAM;
`Buffer::system(DmaBuffer, read_only)` wraps pinned system pages and
`Buffer::uncached()` forces MTYPE_UC. `create_vm().await -> Vm` binds a free
VMID (1–15, round robin) to a new zeroed PDB2 root and invalidates it.
`map(&Vm, Mapping { va, offset, size, flags }, Arc<Buffer>).await` takes
hole-stripped, page-aligned addresses below 2^48 and `AMDGPU_VM_PAGE_*`/MTYPE
flags (PRT refused; overlap is `Invalid`). It builds GMC10 four-level tables
(PDB2→PDB1→PDB0→PTB, 512 entries, PDE = physical | VALID, no BFS/TF) in owned
VRAM, encodes PTEs as `gmc_v10_0_get_vm_pte` does, and invalidates the VMID on
both hubs. `unmap(&Vm, va).await` clears an exact mapping and releases its
buffer only after both ACKs; `destroy_vm(Vm).await` repoints the context to
the empty root, invalidates, then frees tables and buffers. A VM holds only
buffers explicitly mapped into it; its tables are never client buffers; each VM
is capped at 1024 table pages. `vm_info(&Vm)` reports the VMID, generation and
`page_table_base` a ring flush would program.

Every TLB invalidation uses engine 17 per hub (GFX then MM), HDP flush first,
MMHUB semaphore around the request, 100 ms bounded waits on `1 << vmid`.
Entries are 64-bit stores; new tables are zeroed and HDP-flushed before their
PDE is written. Validation/allocation errors (`Invalid`, `Allocation`,
`Exhausted`) touch no hardware. After the first hardware access, timeout,
revocation, removal or cancellation latch `runtime()` at `Failed`/`Busy`: every
later operation returns `Busy`, the semaphore is not released, and all touched
buffers/tables are retained.

`Fault::decode(client, source, vmid, src_data)` accepts UTCL2 (0x1b, GFX hub)
and VMC (0x12, MM hub) source 0, as `gmc_v10_0_process_interrupt` decodes them.
`handle_fault(Fault)` reads `L2_PROTECTION_FAULT_STATUS`, re-arms it via
`FAULT_CNTL` bit 0 and returns `FaultOwner::{Kernel, Vm { vmid, generation },
Unowned}`, recording `FaultInfo` (latest address/status, count) for
`vm_fault(&Vm)`. Retry faults are reported, never recovered. Fault interrupts
stay masked until the IH owner calls `set_fault_interrupts(true)`;
`Fault::from_iv(&ih::Iv)` adapts IVs from `ColdBoot::interrupts()` subscriptions
to `ih::source::{VMC_FAULT, UTCL2_FAULT}`.
`ColdBoot::memory()` exposes this owner after `FirmwareReady`/`Released`.

### Shared discrete RDNA2 SDMA0 execution proof

`unsafe amdgpu_sdma_navi22::Sdma::new_rdna2(gpu, pci_cap, pool)` validates the
exact per-ASIC GC and SDMA0 versions before allocating a ring. Navi21/22/23/24
use Linux's SDMA5.2 backend; SDMA0's registers are relative to GC base index 0,
not the standalone discovery SDMA base. NBIO2.3 and HDP5 register windows must
also be supported and bounded. Construction performs no device I/O. The
existing `Sdma::new` entry point keeps the strict Navi22 PCI gate.

The existing `unsafe initialize(&mut gmc).await` can then run the shared
translated VRAM write/copy/fence proof with a matching retained GMC owner.
It requires trained VRAM, ready PSP/RLC/SDMA firmware, inactive other engines,
disabled gating and exclusive reset/PM control over the physical GPU. It
uses reported physical VRAM size rather than inherited FB_LOCATION_TOP to
bound its ring and translated test pages. Only SDMA0 is started; this proof
does not enable user submissions, fault/trap interrupts or additional SDMA
instances. Every capability, timeout, cancellation and memory-quarantine
condition below remains in force. Production queues and IH are initialized
separately by the shared coordinator.

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
After verification, crate-internal `trap(context).await` appends one
`SDMA_OP_TRAP` block (INT_CONTEXT masked to 28 bits), sets
`SDMA0_CNTL.TRAP_ENABLE` and waits at most 100 ms for both read pointers to
reach 192 bytes. It runs once; failure marks the engine `Failed`.

### Shared discrete RDNA2 graphics and compute queue proofs

`unsafe amdgpu_cp_navi22::Gfx::new_rdna2` and
`unsafe amdgpu_kiq_navi22::Compute::new_rdna2` accept inventoried Navi21/22/23/24
PCI identities with exact profile GC/SDMA versions and compatible NBIO, HDP
and OSSSYS 5.0.0–5.0.3 banks. Resolution checks all accessed register ranges
before allocation. Existing Navi22 constructors retain their narrower gates.
`Doorbells::map_rdna2` and `enable_doorbell_apertures_rdna2` provide the shared
BAR2 mapping and aperture setup under the existing unsafe ownership contracts.

`Gfx::golden()` selects the ordered Linux GC 10.3.0/2/4/5 register sequence:
43/42/36/32 rows respectively. Unknown GC versions have no sequence. The
sequences retain `gfx_v10_0.c`, including its local register overrides, as
source provenance. Each profile reuses the
bounded graphics ring/IB proof and the two-MEC KIQ/compute ring/IB proof.
Model tests exercise each sequence's masked writes, successful completion,
revocation and replay rejection. The shared coordinator combines these APIs
with interrupt, board-power and display initialization for native startup.

### Navi 22 OSSSYS 5.0.3 interrupt ring and dispatch

`unsafe amdgpu_ih_navi22::Ih::new_rdna2(gpu, pci_cap, pool, bus_device)`
reserves the same RB0 owner for exact Navi21/22/23/24 PCI and GC identities,
compatible NBIO/HDP banks and discovered OSSSYS 5.0.0–5.0.3. Layout resolution
precedes allocation, interrupt routing and device I/O. The caller must own the
physical function and its matching permanent VRAM pool exclusively. Unknown,
missing, duplicate or out-of-range banks are rejected. The original `new`
retains its Navi22/OSSSYS 5.0.3 gate.

The shared backend follows Linux `navi10_ih`: only RB0 is allocated; the
self-IV timeout/threshold programming on enable and disable is skipped before
OSSSYS 5.0.3. This is selected from discovery rather than inferred from the PCI
marketing name. Family models exercise dispatch and shutdown with MSI enabled
and disabled for every supported OSSSYS revision. The compatible-version
list retains Linux's IH backend selection as source provenance.
This constructor does not broaden native probing or enable engine IRQ sources.

`unsafe amdgpu_ih_navi22::Ih::new(gpu, pci_cap, pool, bus_device)` validates
OSSSYS 5.0.3, NBIO and HDP 5.0 banks and reserves a 256 KiB VRAM ring plus a
writeback page and a host NBIO dummy page, without I/O. Only RB0 exists, as in
Linux for navy_flounder. `unsafe initialize().await` requires ready GMC VMID0.
It routes MSI-X entry 0, else MSI, else polling (`Delivery`). Then it follows
`navi10_ih_irq_init`: it disables the ring (inherited enables are recorded in
`Status::inherited`), runs nbio_v2_3 `ih_control`, and programs
base/`IH_RB_CNTL` (MC_SPACE 4, 2^16-dword ring, writeback, overflow
enable/clear, snoop, RPTR_REARM only with MSI) and the OSSSYS 5.0 WPTR_ADDR
HI/LO (offsets swapped vs 4.0). It zeroes the pointers, disables the
IH doorbell and NBIO doorbell range, then enables ring/interrupt and the
5.0.3 self-IV wptr timeout. The ring is in VRAM through the VMID0 system
aperture, not GTT; rptr goes through `IH_RB_RPTR` because BAR2 is not mapped.
`unsafe disable().await` mirrors `navi10_ih_irq_disable` with a 1 ms settle.
It masks the vector and closes every waiter with `Closed::Disabled`; it does
not reuse the ring.

`Ih::handle()` returns a cloneable `Handle`. `subscribe(Source{client,src})`
claims the only route for that pair, before or after enable (a second owner
gets `Busy`). It returns a generation-tagged `Subscription` with a 64-IV
mailbox that drops the oldest entry when full (`lost()`). `try_next()` and
`wait().await` deliver queued IVs before a terminal `Closed`
(`Revoked`, `Disabled`, `DeviceLost`, `AuthorityRevoked`, `Failed`).
`revoke(source)` retires the current generation; a stale handle never sees a
newer owner's IVs. `close(reason)` lets other owners report device loss.
`drain()` runs `navi10_ih_get_wptr` (writeback, register on RB_OVERFLOW,
resume at wptr+32, clear pulse) and decodes up to 8×32 SOC15 IVs per call
(`Iv`, with `cp_queue`, `page_fault`, `hpd` helpers). It skips client ids
≥ 0x20, all-ones and misaligned entries as malformed and writes the rptr back.
It runs in task context only: the IRQ handler records a count, and waiters
drain on wake or on a watchdog (10 ms with MSI, 1 ms polling).
All-ones registers or revoked authority close every waiter. `Stats` exposes
interrupts, drained, unhandled, malformed, overflows, dropped, unsignalled
(found without an interrupt) and watchdog counts. `source::*` holds the GFX
EOP/fault, SDMA traps, VMC/UTCL2 faults, DCN vblank (VSTARTUP)/vupdate/pflip/
HPD/DMUB-outbox and SMU11 thermal/CTF/MP1 ids.

### Navi 22 kernel queues: GFX, KIQ/compute and SDMA

`unsafe amdgpu_cp_navi22::enable_fence_interrupts(gpu, pci_cap, doorbells)` sets
`TIME_STAMP_INT_ENABLE` for ME0 pipe 0 and MEC1 pipe 0 and `TRAP_ENABLE` on both
SDMA engines, the sources Linux's fence driver arms with `amdgpu_irq_get` (the
KIQ stays polled). `Stage::FenceInterrupts`, the final ColdBoot stage, runs it
once every queue is verified, then subscribes to `GFX_EOP`, `SDMA0_TRAP` and
`SDMA1_TRAP` and spawns one forwarder per source that calls
`amdgpu_fence_navi22::notify` for the decoded engine (`notify_all` on a
terminal IH error). A subscription failure only logs; fences keep polling.

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

### Navi 22 runtime power, thermal and recovery

`amdgpu_smu_navi22_telemetry` decodes the SMU11 (`smu11_driver_if_sienna_cichlid.h`)
`SmuMetricsExternal_t` (200 bytes, `TABLE_SMU_METRICS` = 5). `Layout::for_firmware`
selects `SmuMetrics_V2_t` for MP1 11.0.11 PMFW >= `0x412D00` and `SmuMetrics_t`
otherwise, as `sienna_cichlid_get_smu_metrics_data`; V2 throttling percentages
fold into the THROTTLER bit mask. `Metrics` carries edge/hotspot/mem/VR
temperatures (m°C), `CurrFanSpeed`, `AverageSocketPower` (W), the busy-threshold
(15 %) GFXCLK average, FCLK/UCLK post-DS averages, `CurrClock` entries and
activity. `Limits::from_table` reads `TemperatureLimit`, `FanMaximumRpm` (only
with FEATURE_FAN_CONTROL) and `SocketPowerLimitAc[PPT0]` from the uploaded
1668-byte `PPTable_t`, plus the powerplay header's `software_shutdown_temp`,
`thermal_controller_type` and HARDWAREDC cap; `*_emergency` adds `CTF_OFFSET`
(5 °C) and a zero/255 limit is refused.

After boot power setup, `Smu::read_telemetry().await` zeroes and HDP-flushes the
retained `DriverDramAddr` buffer, sends `TransferTableSmu2Dram` (0x12, table 5),
invalidates HDP (`HDP_READ_CACHE_INVALIDATE`) and decodes the table, then reads
the running features, `GetPptLimit` (0x33, PPT0/AC; the table limit when PPT is
not running or the query is rejected), `SMUSVI0_TEL_PLANE0` VDDCOR
(`smu_v11_0_get_gfx_vdd`) and the THM `CG_FDO_CTRL1`/`CG_THERMAL_STATUS` PWM
duty (`smu_v11_0_get_fan_speed_pwm`). Runtime commands move `PowerReady`/
`DisplayPowerReady` through `Runtime`: a clean rejection restores the state,
timeout, revocation, all-ones sensors or cancellation are terminal.
`Smu::protected(enabled)` checks that the PPT/TDC/VR0HOT/FW_CTF/FAN/THERMAL
features running at boot still run. `ColdBoot::power_limits()` and
`power_sample().await` expose this after `FirmwareReady`.

`amdgpu_navi22_platform::run` then starts `amdgpu_navi22_power`: the shared
`amdgpu_hwmon` node `/sys/class/hwmon/hwmon<N>` named `amdgpu` and a 1 s
monitor that takes the owner lock per refresh. Attributes are the Linux SMU11
dGPU set, read-only: `temp1..3` (edge/junction/mem) with crit/crit_hyst
(-273150)/emergency; with a fan `pwm1` (register duty), `pwm1_enable` 2,
`pwm1_min/max`, `fan1_input/min/max/target`, `fan1_enable` 0; `in0` vddgfx;
`power1_average/cap/cap_default` (µW; default is the first PMFW limit, else the
table's AC limit); `freq1` sclk and `freq2` mclk (Hz). Fan control stays in
PMFW automatic mode. The monitor logs throttling start/end, lost protection,
the first failed refresh and hotspot at `software_shutdown_temp`; shutdown
policy belongs to the thermal interrupts below. Model-tested only.

`Smu::enable_thermal_alert().await` (`ColdBoot::enable_thermal_alert`) follows
`smu_v11_0_enable_thermal_alert`: with a nonzero `thermal_controller_type` it
programs `THM_THERMAL_INT_CTRL` (MAX_IH_CREDIT 5, IH_HW_ENA, INTH/INTL and
TRIGGER unmasked, DIG_THERM_INTH = min(255, `software_shutdown_temp`),
DIG_THERM_INTL = 0), clears `THM_THERMAL_INT_ENA` (INTH/INTL/TRIGGER_CLR),
sets `MP1_SMN_IH_SW_INT.ID` 0xFE and unmasks `MP1_SMN_IH_SW_INT_CTRL`; with a
GPIO-signalled DC cap and FEATURE_ACDC running it sends `ReenableAcDcInterrupt`
(0x34). It returns `Alert { armed, window, acdc_rearmed }`; `InterruptAck`
sets `INT_ACK` without the mailbox. After telemetry, `run` subscribes the four
`smu_v11_0_register_irq_handler` sources (THM 0x0f src 0/1, ROM_SMUIO 0x16 src
83, MP1 0x1f src 0xfe) *before* arming them and spawns one task per source
(`amdgpu_navi22_thermal`). L2H waits 50 ms (`AMDGPU_SWCTF_EXTRA_DELAY`),
re-reads the hotspot and, at or above `software_shutdown_temp` — or with no
reading or no limit, as `smu_swctf_delayed_work_handler` — logs the SW CTF and
powers off; H2L only logs; GPIO19 CTF logs and powers off at once; SMU-to-driver
acknowledges, then AC/DC (3/4) re-arms AC/DC and thermal throttling (7) counts.
NARF has no userspace poweroff helper or write-back, so `orderly_poweroff(true)`
reduces to its forced fallback, `narf_power::system::power_off()`.
`amdgpu_navi22_thermal::status()` (also in platform `Diagnostics::thermal`)
reports the alert, per-source counters and any shutdown reason.

Hang detection (`amdgpu_navi22_tdr`) follows drm_sched's per-ring job timeout
with Linux's default `lockup_timeout` of 2 s for every queue. After a boot whose
queues all verified, a task samples every 250 ms, under the owner lock,
`Progress { engine, emitted, signaled }` of GFX, KIQ, compute and SDMA0/1
(`ColdBoot::queue_progress`: the queue's last sequence and its fence writeback
after an HDP invalidate; an all-ones read-back is device loss). The per-engine
timer starts when unsignalled work is first seen and restarts on every fence
advance; a stall past the timeout logs `ring <engine> timeout, signaled seq=…,
emitted seq=…` once and is retained in `tdr::status()`. Detection is always on.
`unsafe tdr::set_automatic_recovery(bool)` (Linux `amdgpu_gpu_recovery`) makes
a detected hang call `recover()`; the fb boot handoff enables it on RX 6000
unless `amdgpu.gpu_recovery=0`, after installing the console hook below. At
most `tdr::MAX_AUTOMATIC_RECOVERIES` (3) automatic recoveries run per boot,
because each one quarantines the old owners' VRAM; past that the stall is only
logged. Explicit `recover()` calls are not counted.

`amdgpu_navi22_platform::set_recovery_console_hook(fn(bool))` installs the
fb owner's pause (`true`) / resume (`false`) of every kernel CPU writer of the
boot framebuffer. `recover()` pauses through it before the reset, withdraws
the runtime power controls, and after success resets the requested power
opt-in to none, republishes the controls and resumes the console; a lost
device keeps the console quarantined. User CPU mappings of VRAM are not
revoked during a reset, as in Linux (their accesses reach an unresponsive BAR
and the contents are lost).

`unsafe amdgpu_navi22_platform::recover().await` is
`amdgpu_device_gpu_recover` for mode1 (`amdgpu_navi22_recovery::Recovery`, state
stored outside the future). `check` refuses (`Unsupported`, no side effects) a
boot that needed GDDR6 training (no short-training replay yet) or lacks a board
table, PSP or IH. Quiesce stops TDR, telemetry and thermal, disables the IH ring
(every subscriber gets `Disabled`) and calls `amdgpu_fence_navi22::abandon_all`,
which ends every pending fence wait with its error. Reinitialize consumes the
owner (`ColdBoot::into_recovery`: same snapshot, authority, pool and prepared
firmware; old owners dropped without I/O, their VRAM quarantined), prepares a
`Reset::new_recovery` — the reset-on-init core without the SOS shortcut — plus
fresh hubs, SDMA proof, IH and queues on the same BAR2 doorbells, stores it,
and runs the complete cold-boot sequence including ring/IB tests. Restart
re-arms telemetry, thermal and TDR. DMUB/display are not restarted: the screen
stays dark until the display owner restarts DMUB and modesets. Any failure or
cancellation is terminal `Lost`: services stop, fence waits are abandoned and
the old and new IH endpoints close with `DeviceLost`. `recoveries()` counts
successes; platform `Diagnostics` adds `tdr` and `recovery`. Model-tested only.

`amdgpu_navi22_power_policy::Policy` is the typed hook for the power savings
Linux enables by default on sienna_cichlid — GFXOFF, SoC clock gating
(`ClockGating`: MMHUB/ATHUB/HDP/IH/SDMA/SMUIO), GC clock gating
(`GfxClockGating`), MMHUB/ATHUB power gating, memory (UCLK) and fabric (FCLK)
DPM and deep sleep. `requirement` states what each needs: SMU feature bits,
display admission (`DisplayAdmission`: watermark sets/PMFW watermark table,
DML DRAM- and FCLK-change support, stutter with the deep-sleep DCEFCLK floor,
bandwidth floors) and driver readiness (GFXOFF-safe GC access, RLC safe mode,
validated recovery). `Policy::new()`/`Default` disable everything; `request`
refuses with `NotValidated` while `HARDWARE_VALIDATED` is false.
`OptIn::parse(Option<&str>)` reads the `amdgpu.rdna2_pg=` value, or
`DEFAULT_POWER_SAVING` when it is absent (tokens
`gfxoff`, `cg`, `gfxcg`, `hubpg`, `memdpm`, `fclkdpm`, `ds`, `wm`; any unknown
token yields `OptIn::NONE`), and `request_opted_in(feature, admission, driver,
optin)` opens a gate only for a named feature whose display and driver-software
prerequisites hold (`NotOptedIn` otherwise), waiving only the hardware
validation facts. `revoke` closes a gate.

`amdgpu_navi22_power_saving::plan(optin, admission, driver) -> Plan` evaluates
every feature (pure; `Plan::blocks`, `smu_enable`, per-feature `refusals`);
`readiness()` reports RLC safe mode implemented, recovery unvalidated and GC
access GFXOFF-safe only after `amdgpu_navi22_gfxoff::declare_submission_guarded`.
`amdgpu_navi22_platform::power_saving(value)` (fb calls it with the boot
argument's list, or the default list) runs `ColdBoot::apply_power_saving`: optional PMFW
watermark upload (`amdgpu_dcn30_watermarks`: `navi22_ranges`, `encode`,
`notify` over the DAL mailbox, as `dcn3_notify_wm_ranges`), clock gating
(`amdgpu_navi22_gating::Gating::set_clockgating(gate, Blocks)`, Linux IP order
common→gmc→ih→gfx→sdma, reverse to ungate, GC under RLC safe mode),
`Smu::update_gating_features(mask, enable)` (only `GATING_FEATURES`,
smu_cmn_feature_update_enable_state with running-set and protection checks),
the initial `DisallowGfxOff`, and UCLK/FCLK hard minimums at the admitted
floors (`ClockManager::hard_min`). It then starts the GFXOFF controller.
An all-ones gating read logs its discovery block, BAR5 byte address and the
number of register writes by that gating owner. Status/control reads fail
with `DeviceGone`. RLC_CGTT_MGCG_OVERRIDE alone is a full-word RMW operand:
an all-set value is retained only after a fresh RLC_CNTL read proves the
RLC F32 is running; a missing or halted RLC still refuses programming.
The gating owner remains terminal `Failed`: earlier IP blocks may already be
programmed, and no successful rollback is implied. Failure returns before
subsequent SMU feature enables, floor reductions or GFXOFF startup.
`apply` may run again after `remove` (`replace_power_saving`), reusing the
published PMFW watermark table and the gating owner; a set that is still
applied refuses `Busy`.

Runtime controls (`amdgpu_rdna2_power_controls`) back two DRM card sysfs
attributes through `DrmCard::{performance_level, set_performance_level,
pp_features, set_pp_features}` (defaults: `"auto"`, `Unsupported`, `None`,
`Unsupported`; `AmdgpuCard` serves RX 6000 PCI IDs). `publish().await` (fb,
after power saving; recovery, after success) samples the PMFW running mask
and marks the controls ready; `withdraw()` clears that. Writes validate
synchronously (`EINVAL` malformed, `ENODEV` before publication, `EOPNOTSUPP`
unsupported, `EPERM` forbidden bits) and queue the change to a task;
`CONTROL` serializes changes and a newer write of the same attribute
supersedes one not yet started. Reads report the applied state.
- `power_dpm_force_performance_level`: `auto|low|high` move GFXCLK only
  through `Smu::set_gfx_level(GfxLevel)` (`smu_v11_0_set_soft_freq_limited_range`:
  SoftMax then SoftMin, `PPCLK_GFXCLK << 16`, 0xffff/0 automatic bounds,
  `high`/`low` pinned to the live DPM range). Memory/SoC clocks stay at the
  display owner's floors; `manual` and `profile_*` are refused.
- `pp_features`: show is `smu_cmn_get_pp_feature_mask`'s text over
  sienna_cichlid's 43 mapped feature bits. A write is a hex mask; bits outside
  `power_policy::policy_smu_bits()` must equal the running mask, each policy
  feature's bits must be all set or all clear (`OptIn::with_smu_mask`), and the
  resulting opt-in (clock gating and watermarks kept) replaces the applied one
  through `replace_power_saving`, so enabling still passes every admission
  gate. `Smu::running_features` is `smu_cmn_get_enabled_mask`.
`remove_power_saving` stops GFXOFF and undoes the rest in reverse;
`ColdBoot::power_saving()` reports what was applied.

`amdgpu_navi22_gfxoff` mirrors `amdgpu_gfx_off_ctrl`: request count starting
at 1, `DELAY_MS` (100) before `AllowGfxOff`, cancellation by a disable request,
`DisallowGfxOff` before the count rises, imbalance refused, failed or cancelled
disallow terminal. `Reference::acquire().await` is the disable reference every
GC MMIO path (queue submission, `READ_MMR_REG`, the TDR sampler) holds; it is
a no-op without the opt-in, and must not be awaited with the platform owner
lock held. Recovery calls `forget_for_reset`; `status()` is diagnostic.

### Navi 22 VCN 3.0 and JPEG 3.0

`amdgpu_discovery::parse_vcn_harvest(blob)` returns the harvested VCN mask from
the discovery `HARVEST_INFO` table (zero offset: none; bad signature/checksum:
`BadHarvestTable`). `amdgpu_vcn_navi22::Harvest::navi22(table, revision)` adds
Linux's Navy Flounder VCN1 quirk (revisions C1/C2/C3/C5/C7/CF/DF);
`unsafe Harvest::read(gpu, pci_cap, revision)` re-reads the 10 KiB discovery
copy at boot. The platform applies it to the firmware set; an unreadable table
disables media only.

`unsafe Media::new(gpu, pci_cap, pool, doorbells, instances, firmware_bytes)`
resolves each instance's VCN BASE_IDX 0/1 banks from discovery (3.0.0 at
0x7800/0x7E00, 3.0.1 at 0x7B00/0x12000), GC/NBIO/HDP, and reserves per instance
the VCPU BO (128 KiB stack, 512 KiB context, 4 KiB fw_shared), 4 KiB decode and
two encode rings, writeback and IB-test buffers (below 2^40), plus an 8 KiB JPEG
ring when instance 0 exists. No I/O. Doorbells are 32-bit: decode
`0x310 + 8i`, encode j `0x312 + j + 8i`, JPEG `0x311`, with NBIO MMSCH0/1
ranges (size 8). `unsafe start(MediaFirmware, Option<PowerStatus>)` refuses a
missing per-instance TMR address or a running SMU MM_DPM_PG feature before any
write, then per instance zeroes the BO, sets fw_shared flags, programs the
range and runs `vcn_v3_0_start`'s static path with power gating disabled
(PGFSM all tiles on before any UVD_STATUS read, no UVD_PG_EN; Linux's default DPG mode is not used),
MGCG-style clock-gating disable, PSP-TMR cache window 0, VCPU boot with Linux's
10-reset retry loop (100 × 10 ms samples each), decode RBC and both encode
rings, then the SCRATCH9 decode and VCN_ENC_CMD_END encode ring tests.
VCPU_CNTL masked writes preserve the original unselected bits, including an
all-ones control word, as Linux's WREG32_P does. Before accepting that value,
the owner checks NBIO's memory-size and doorbell-aperture registers and requires
nonzero memory and an enabled aperture; loss refuses the write. A gated GC
register is not a presence probe. Status and wait-register
all-ones reads still fail rather than proving readiness.
`unsafe start_jpeg()` honours CC_UVD_HARVESTING, powers UVDJ on and runs
`jpeg_v3_0_start` plus the JPEG pitch ring test. `test_ib()` runs the decoder
create/destroy message pair and the encoder session initialize/close pair on
every started ring and waits (1 s) for the fences; register waits are bounded
by 100 ms. `unsafe stop()` runs `vcn_v3_0_stop`/`jpeg_v3_0_stop` without
re-enabling power gating. Each operation has one predecessor state;
failure, cancellation, revocation and device loss are terminal and retain
published memory. `status()` returns `Status { state, jpeg, proof }`.
`route_interrupts(ih, status)` subscribes the started rings' VCN/VCN1
(client 0x10/0x0e: 124 decode, 119/120 encode) and JPEG (153) sources and
forwards them to `amdgpu_fence_navi22::Engine::{Vcn0, Vcn1, Jpeg}`.

`amdgpu_video_caps_navi22::{codecs, caps}(kind, harvested)` return Linux's
Sienna Cichlid `AMDGPU_INFO_VIDEO_CAPS` tables (decode VCN0 with AV1, or VCN1
when VCN0 is harvested; encode AVC 4096² and HEVC 8192×4352) as
`DrmAmdgpuInfoVideoCaps`; `None` for an unknown subquery or no VCN.
`AMDGPU_INFO_VIDEO_CAPS` answers from them with `Published::vcn_harvest`
(`amdgpu_info::publish_navi22_vcn_harvest`, the harvest the platform read)
plus every VCN instance absent from discovery: on the RX 6750 XT (VCN1
harvested) decode is the VCN0 table, AV1 included.

Client media rings (append-only additions; only while `accel` is on, the
default):
`Media::{client_rings() -> u8, fence_reader() -> MediaFenceReader,
submit(MediaRing, VmRef, &[Ib], copies),
client_fences(MediaRing) -> (completed, throttle)}` (and
`ColdBoot::{client_media, submit_media, media_fences}`) queue client jobs on
instance 0's decode ring, both encode rings and the JPEG ring once their ring
and IB tests passed. `amdgpu_navi22_submit::{MediaRing, encode_media,
validate_media, media_grant, MEDIA_MAX_IBS}` frame them as Linux's
`amdgpu_ib_schedule` does for vcn_v3_0/jpeg_v3_0: when the job's MMHUB grant
flushes, (decode/JPEG `insert_start`,) the MMHUB
`gmc_v10_0_emit_flush_gpu_tlb` (invalidation semaphore acquire, PTB LO/HI,
request/ACK, release), the ring's PTB-write wait and, when the grant remaps
the PASID, the `IH_VMID_<vmid>_LUT_MM` write; then `insert_start`, the IBs under the VMID
(`vcn_v2_0_dec/enc_ring_emit_ib`, `jpeg_v2_0_dec_ring_emit_ib`), the fence on
the kernel ring's sequence and `insert_end`/`VCN_ENC_CMD_END`. MMHUB
invalidation engines follow `amdgpu_gmc_allocate_vm_inv_eng` over ring order
(dec 0, enc 1/4, JPEG 5 with VCN1 harvested, 8 otherwise). JPEG IBs run from
a kernel copy (`JPEG_IB_SLOT`, 64 KiB per outstanding job) at VMID 0 with
data at the client's VMID; the JPEG fence is `JPEG_FENCE` in the JPEG
reservation. Two jobs outstanding per ring; frames are bounded to half the
ring. Not emitted: the post-flush VM fence (Linux bookkeeping; the job's own
fence stands in, as on the kernel queues).

`amdgpu_vcn_navi22_cs::{media_ring, ring_id, completed, rings, register,
unregister, forget_owner, submit, dec_ib_messages, check_dec_msg,
parse_jpeg_ib, Sessions}` carry the CS side: `AMDGPU_HW_IP_VCN_DEC/ENC/JPEG`
ring 0 of instance 0 map to ticket ring ids 4/5/7 (`FIRST_ID + index`);
jobs with a user fence are refused (`no_user_fence`); decode IBs (at most
`DEC_IB_MAX_DWORDS`) are scanned for messages as
`vcn_v3_0_ring_patch_cs_in_place` and each checked as `vcn_v3_0_dec_msg`
(8-byte alignment, 4 dwords, header and create buffers inside the mapping,
buffer indices inside the claimed length; `NeedsVcn0` when VCN0 is
harvested and the codec is not H.264/HEVC/VP9), on every instance; decode
sessions follow `amdgpu_uvd_cs_msg`'s handle rules per client (create: free
handle or EINVAL/ENOSPC, `MAX_SESSIONS` 40; decode/destroy: own handle or
EINVAL/ENOENT), all or nothing per job and rolled back when the job never
reaches the ring, and forgotten when the client's `VmState` drops; JPEG IBs
pass `amdgpu_jpeg_dec_parse_cs` on the kernel copy; encode IBs are not
parsed.

### Navi 22 client submission and render ABI

`amdgpu_navi22_submit` queues client IBs on the verified kernel queues:
`Gfx::submit`, `Compute::submit`, `Sdma::submit(instance, ..)` (and
`ColdBoot::submit(ring, &mut RingState, VmRef, context, &[Ib])`,
`ColdBoot::fences(ring) -> (completed, throttle)`) emit what the job's VMID
grant asks for — `VmRef { vmid, page_table_base, pasid, flush, map_pasid }`:
a ring-side VM flush (PTB write + GFXHUB invalidation on the ring's engine:
gfx 0, compute 4, SDMA 13/14; PFP_SYNC_ME on gfx) when `flush`, the
`IH_VMID_<vmid>_LUT` ← PASID write (`gmc_v10_0_emit_pasid_mapping`, at the
queue layout's OSSSYS base) when `map_pasid` — preceded by a pipeline sync
when the job flushes or its context differs from the ring's previous job's
(`RingState`), then CONTEXT_CONTROL/FRAME_CONTROL on gfx, up to 16 IBs with
the VMID, then the ring fence. `validate` refuses VMID 0/>15,
empty or oversized IB lists, unaligned or zero-length IBs. At most two
submissions are outstanding per ring; a third returns `Busy` without
touching the ring.

`amdgpu_navi22_cs::{register, unregister, Submitter, ring_id, ring_index,
job_done, drm_card}` plug the card into the generic render path: after a cold
boot or recovery whose queues are verified, `register` borrows the GFXHUB
client VMIDs 1–7 (`ColdBoot::reserve_client_vmids` →
`Gmc::reserve_client_vmids() -> ClientVmids`; 8–15 stay KFD's,
`FIRST_KFD_VMID`), registers the card's client VRAM heap
(`ColdBoot::reserve_client_vram`, retained across recoveries) with
`amdgpu_gem::register_vram_heap`, and an `amdgpu_cs::Submitter` whose jobs run
on gfx ring 0, the compute queue (rings 0–3) or SDMA 0/1 under a VMID granted
per job by the generic `amdgpu_vmid::VmidManager` (`grab_request`, `vm_ref`,
`vmid_manager`, `entity` build its inputs): a space reuses its VMID without a
flush until it removes a mapping or changes root, a job waits (bounded, then
`EBUSY`) when no VMID is idle, and the LUT entry is rewritten only when the
VMID last mapped another PASID. `Gmc::handle_fault` charges faults on lent
VMIDs to the IV's PASID (`Fault::pasid`, `FaultOwner::Client`,
`amdgpu_vmid::record_fault`), which `AMDGPU_INFO_GPUVM_FAULT` reports. A
recovery's new submitter starts with a fresh manager, so every VMID flushes
and remaps again. Media jobs (VCN decode/encode, JPEG) run through
`amdgpu_vcn_navi22_cs` on ticket ring ids 4–7 under a second, MMHUB
`VmidManager` over the same lent VMID numbers (`register(boot, first,
last)`), whose PASID remap is honoured only together with a flush
(`amdgpu_navi22_submit::media_grant`, as `amdgpu_vm_flush` on rings without
`emit_pipeline_sync`) and written to `IH_VMID_<vmid>_LUT_MM`. Tickets are
`ring_index(epoch, id) << 32 | seq` with three ring-id bits (`RING_IDS` 8);
tickets of an earlier recovery epoch read as complete. `amdgpu_vm::VmState`
tracks eight ring slots. Fences are read
by `amdgpu_cp_navi22::FenceReader` (`ColdBoot::client_fence_reader`) without
the owner. `unregister` runs at the start of recovery.

Generic paths it uses (shared with Navi48): the `FENCE` chunk
(`Submission::user_fence`, written with the job's ticket when `retire` frees
it), `GEM_METADATA`, PRIME export/import of amdgpu GEM objects
(`AmdgpuDmaBufFile`, `GemState::import`), CPU-mapped GEM lifetime
(`GemState::mapping_object`) and implicit sync on `BO_HANDLES`-listed
buffers, whose fence contexts are the Navi 22 ticket ring indices.
`HW_IP_INFO` keeps the Navi 22 multi-ring mask (`amdgpu_info_navi22`) while
the card's submitter serves the IP, and reports 0 otherwise. Navi 22 shares
the `amdgpu_vmid` reuse with Navi48.
`GEM_MMAP` returns its offset at byte 0 of the 8-byte union;
`drm_ioctl_bridge::{get_client, without_kms}` answer `GET_CLIENT` on primary
nodes and `VERSION`/`GET_CAP` on amdgpu nodes without KMS state;
`SYNCOBJ_WAIT` returns `-ETIME` on timeout and `-EINVAL` for an unsubmitted
syncobj without `WAIT_FOR_SUBMIT`; `amdgpu_ctx` QUERY_STATE/QUERY_STATE2
report recoveries.

### Navi 22 DCN3.0 DMUB startup

`amdgpu_dmub_navi22::Prepared::new(image, vbios, psp_version)` parses the
combined Navy Flounder DMCUB image and stages ordinary RAM before device I/O.
`Image::prepare_dcn30` requires IP 3.0, cached-inbox firmware newer than 1.10.0,
and no separate BSS/shared-state mapping. It uses the existing bounded layout
builder; legacy/unsupported layouts fail before any hardware operation.
`unsafe Dmub::new(gpu, pci_cap, pool, prepared)` bounds DCN3.0 base index 2,
NBIO and HDP 5.0.x, then reserves owned VRAM. It requires exclusive physical-GPU ownership,
permanent mappings, and firmware/VBIOS belonging to this board.

`quiesce().await` checks the DMUB enable fuse (`Error::Unsupported` when the
DMCUB is fused off: the boot drops the DMUB owner and continues, as
`dm_dmub_hw_init` does), requests `STOP_FW` unless DMCUB is already held in
reset, and waits up to 100 ms for the GPINT acknowledgement and stop reply.
Like `dmub_dcn20_reset`, a timeout is logged and the reset forced.
It holds DCN3.0 `DMCUB_CNTL.SOFT_RESET` (bit 17) and `MMHUBBUB_SOFT_RESET`
(dword `0x341`, bit 8), disables execution, and clears mailbox pointers/status.
It never uses DCN31's separate CNTL2 reset or dword `0x342` hub reset.

After PSP loads DMCUB, `unsafe start(&Psp).await` validates that execution is
still reset and security reset is released. When readable, both PSP
instruction/stack windows must be enabled and wholly inside either the retained TMR or their respective
pre-inventoried secure CW0/CW1 reservation after checked GPU-physical translation.
If PSP programmed fresh windows after that inventory, CW0 must contain the
complete authenticated image from this PSP session's reply. Each new full
CW0/CW1 range must fit the matching retained GPU pool and be permanently
excluded without overlapping any live or retired allocation before startup.
The prepared signed-image size must match the PSP upload; the executable
CW0 extent excludes the parsed PSP header/footer, matching Linux's DMUB
instruction-window sizing. The original signed range stays reserved.
Each full window must fit one reservation; a point address, unrelated protected
client, inter-window gap or enlarged inherited window is insufficient.
On hardware where all eight secure CW0/CW1 registers read as zero, the
completed PSP load is the placement authority, as on Linux's PSP path. This
case requires a zero PSP response status for the matching session's complete
authenticated signed image,
the prepared upload-size match, and retained ownership of its full extent:
TMR, inherited CW0, or a bounded claim in that GPU's pool without any live or
retired overlap. A plain TMR range without an authenticated PSP reply, partial
zero readback, or an image outside the owned memory does not authorize this
path. No secure-window addresses are inferred from zero readback or the entry
point. PSP remains responsible for those secure windows; the TMR and full
signed-image claim stay retained. Fresh firmware-ready and mailbox proof are
still required before readiness is published.
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
Linux ABI without enabling any advertised feature; `fams_version()` is
`fw_assisted_mclk_switch_ver`, and `Dmub::fams2()` reports whether DC keeps
FAMS2 on (version 0x41, FAMS 2.1; `None` before the query answered).
`Dmub::hw_lock(lock)` is dcn401_dmub_hw_control_lock's inbox0 HW lock
(HW_LOCK command code 1 with the lock or release bit; SCRATCH17 cleared,
INBOX0_WPTR written, a 100-ms acknowledgement). As
dc_dmub_srv_wait_for_inbox0_ack, a missing acknowledgement is logged and
the caller goes on: `Ok(false)`, the mailbox left usable (DC's DMU recovery
on that timeout is off by default). `fams2_config_commands(enable,
&Fams2Global, &[Fams2StreamConfig])` lays out
dc_dmub_srv_rb_based_fams2_update_config's FAMS2_CONFIG list (type 76,
sub-type 4: the global command, then every stream's base and sub-state,
`multi_cmd_pending` on all but the last; disabled, the global command
alone; `global` carries DC's static feature overrides, which the caller
applies: dcn401's debug defaults turn stall recovery and offload flip on and
debug off). As in Linux's
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

`Hubp::initialize(gb_addr_config)` admits only a blank DCN30 pipe with a GC10
256-byte-interleave configuration. It applies `hubp3_init`'s HUBPREQ_DEBUG
ECO and TTU-enable step, then derives DCSURF_ADDR_CONFIG's pipe, compressed
fragment and packer fields from this device's GB_ADDR_CONFIG. Unsupported
profiles, interleaves, a live fetch or missing-device input fail before any
write. The RDNA2 pipeline calls this after domain power-up and HUBP clock
enable, before surface setup. Plane/DSC power-request brackets preserve an
inherited IP_REQUEST_EN and unrelated bits; errors and dropped transition
futures clear only a request that the bracket itself raised. Revocation or
device loss can prevent cleanup and never establish successful retirement.

`amdgpu_dcn30_clk::ClockManager` owns Navi22's separate DAL mailbox and DCCG.
Its unsafe constructor requires the same exclusive physical GPU ownership as
the retained SMU passed to `start`. Before enabling display DPM, it verifies
that all six OTGs and DP streams have retired. SMU then extends its board-bounded
boot policy with UCLK/FCLK/SOCCLK/DCEFCLK and supported memory rail scaling;
autonomous thermal/power/fan protection remains required. Deep sleep, link DPM,
BACO and gating remain excluded. Both owners retain in-flight state across
cancellation and reject replay after incomplete or failed transitions.

`start(smu)` reads the CLK02 PLL at dword `0x17010` and scalar DAL clock levels
(including fine-grained min/max endpoints). Only a successful firmware-version
query establishes the SMU's presence; header/interface mismatches are recorded
and rejected level queries produce empty ranges, as in `dcn3_init_clocks`.
An unusable range is refused by the subsequent clock plan.
`Levels::plan` rounds DISP/DPP requests to DENTIST frequencies within board
limits; `ceiling` supplies their highest representable rates. `prepare(plan)`
requires every stream idle and follows `dcn3_update_clocks`: display-count
notification, DCF floor, deep-sleep hint, UCLK pinned at its upper board state,
then PIX/DISP floors and DISP/DPP divider completion. DCN30's bounding box uses
DCFCLK as its fabric clock; separate SOC/FCLK floors and the unused DF C-state
message are not sent. Refused display-count/deep-sleep notifications are logged
without aborting the modeset, as with Linux's void notification wrappers;
transport errors and rejected, inadequate or out-of-range required floors
still fail before DENTIST programming. Rejection diagnostics retain the
message, argument and firmware response. No running stream changes clocks.
Joint preparation reports the admitted stream count (1–6), including separate
MST streams but excluding extra ODM slices. Runtime PHY and memory/fabric
floors clamp requests to the board minimum and refuse zero, empty ranges and
requests above the board maximum before MMIO. Each required floor must be
acknowledged at a sufficient, in-range frequency. Runtime floors, watermark
messages and the audio PME notification also retain `InFlight` across
cancellation; a late firmware reply does not permit replay. Shared PHYCLK
retains the highest successful link request until GPU restart, so a slower
link cannot lower a faster link's floor; per-link floor release is not yet
implemented. Completed optional
refusals leave the mailbox reusable; transport loss makes it `Failed`.
`pipe_clock` programs a DTO only after successful preparation. No default PLL,
clock table, voltage or memory bandwidth is invented. A failed modeset leaves
floors retained. GDDR6 mode math and the full native pipeline remain separate.
HDMI audio DTO/ACR uses the requested pixel clock halved for YCbCr 4:2:0,
without the PHY PLL's deep-colour scaling (`dce110_populate_audio_dto_parameters`).
Scanout timing retains its original pixel clock.

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
before `run` is polled. The private sequence is heap-owned so consuming and
returning `ColdBoot` during recovery does not put its retained hardware state
or full-size result temporaries on the kernel stack. This copies no physical
ownership: callers must still exclude reset/PM/other clients and retain
permanent mappings for the session.

`ColdBoot::run().await` executes optional reset-on-init → optional memory training → SOS bootstrap →
ring creation → trusted-memory setup → SMC upload → SMU version handshake →
optional board PowerPlay upload → optional DMUB quiesce → graphics upload/autoload → RLC boot check →
optional board calibration/protected GFX DPM setup → optional memory hubs →
optional GART → optional IH enable → optional SDMA execution test → optional SDMA TRAP
interrupt round trip → optional DMUB start → optional kernel queues → fence
interrupts → optional VCN start/ring tests (`Media`) → JPEG (`Jpeg`) → VCN IB
tests (`MediaIbTests`).
Production cold boot emits a serial `start` and terminal `complete` or
`failed` checkpoint for each stage. A pending/cancelled stage emits no false
completion; checkpoints do not run per poll or write training-owned framebuffer
memory. These markers identify startup progress, not native-display readiness.
`unsafe ColdBoot::prepare_reset(device)` adds `Stage::ResetOnInit` before every
firmware stage, as Linux's `nv_need_reset_on_init` does for every posted discrete
Navi: when MP0 C2PMSG_81 shows a running SOS, `amdgpu_reset_navi22::Reset`
caches PCI state (type-0 header, PCIe DevCtl/LnkCtl/DevCtl2/LnkCtl2 and
Resizable BAR controls), clears bus mastering, and issues a mode1 reset through
PMFW (`Mode1Reset`, PMFW >= 58.26) or else through the PSP
(`GFX_CTRL_CMD_ID_MODE1_RST` after TOS ready). After the 500 ms settle — with no
MMIO while config space is reset — it restores and verifies config space,
waits up to 2 s for the PSP bootloader (C2PMSG_35 bit 31) and 100 ms for NBIO
MEMSIZE, and brackets the reset with the ATOM BIOS_SCRATCH_3 engine-hung flag.
A card without running SOS is not reset (`Ok(None)`). Either way the stage then
posts as `amdgpu_device_need_post`/`amdgpu_device_asic_init` do: BIOS_SCRATCH_7
at `adev->bios_scratch_reg_offset` (FirmwareInfo `bios_scratch_reg_startaddr`,
else nbio_2_3 `mmBIOS_SCRATCH_0`) is read; with `ATOM_S7_ASIC_INIT_COMPLETE`
set nothing is written, otherwise (and always in `Mode::Recovery`, as
`amdgpu_device_reinit_after_reset`) ATOM `ASIC_Init` runs from the VBIOS copied
at construction with PS[0]/PS[1] the FirmwareInfo boot-up sclk/mclk dwords,
the atomfirmware FB scratch size, register accesses through the device
authority (past BAR5 via PCIE_INDEX2/DATA2) and every DELAY as a cooperative
sleep, bounded by atom.c's 20 s same-jump guard and 60 s overall. The bit must
read back set. `Report::post` / `Reset::post()` (`Post`: scratch base,
SCRATCH_7 before/after, clocks, opcode/read/write counts, DELAY total,
anomalies) carry the evidence; `Error::Post(PostError)` (NoVbios, Image,
NoClocks, NoAsicInit, Allocation, Atom { error, site }, Timeout, Incomplete) is
terminal like every reset error, and `State::Posting` is retained after
cancellation. The PCI snapshot also keeps MSI address/data/control and the
MSI-X Message Control plus, when it lives in BAR5, the MSI-X table, restored
as `pci_restore_msi_state` (masked enable, table, control). The reset discards
every inherited scanout, so a boot framebuffer on this card goes dark. Failure
or cancellation is terminal for the session. Production boot calls it; the
explicit firmware-only callers may omit it. `Report::reset` carries the method,
PMFW version, SOS values before/after and MEMSIZE.
`ColdBoot::prepare_memory_hubs()` reserves the above VMID0 backing and GART before run;
it requires a prepared board power policy and performs no I/O. Production boot
always calls it. Explicit firmware-only callers may omit this stage.
`ColdBoot::prepare_sdma()` reserves the SDMA ring/writeback before run and
requires prepared memory hubs. Production boot also calls it. `Stage::SdmaTest`
identifies a failure in this stage, with the SDMA error retained.
`Firmware::prepare_dmub(gpu)` prepares board-specific DMUB backing before
construction; `ColdBoot::prepare_dmub()` reserves its VRAM after memory hubs
are prepared. Production boot requires both calls.
`ColdBoot::prepare_interrupts(bus_device)` reserves IH storage after memory
hubs; `interrupts()` (and `amdgpu_navi22_platform::interrupts().await`)
returns its `Handle`. `Stage::InterruptTest` fails the boot only on device
loss or revoked authority. Other failures are printed as `degraded` and
retained in `Report::interrupts` (`Status::proof`); delivery stays on
watchdog/polling. This places `DmubQuiesce`
before any PSP DMCUB upload and `DmubStart` after `FenceInterrupts`, before the
media stages. `DmubStart` (using the GMC-validated `fb_start`/FB offset, as
`dm_dmub_hw_init`'s `soc_fb_info`) includes the runtime version/capability
handshake above; it fails the boot only on device loss or revoked authority,
otherwise it prints `degraded` and the owner stays `Failed`.
`Stage::GoldenSettings` (after `Interrupts`, before `SdmaTest`) applies
`Gfx::golden()` (golden_settings_gc_10_3_2) ahead of SDMA as Linux's GFX
hw_init does; `GfxSetup` then skips them, and `GfxRing` ends with
`gfx_v10_3_set_power_brake_sequence`.
`ColdBoot::prepare_queues(doorbells)` reserves the GFX, KIQ/compute and both
SDMA queue owners after memory hubs and the SDMA proof; production boot calls it
when BAR2 maps. After `InterruptTest` the stages `Doorbells`, `GfxSetup`, `Kiq`,
`ComputeQueues`, `GfxRing`, `SdmaQueues` and `IbTests` follow Linux's
`nv_common_hw_init`, `gfx_v10_0_hw_init`/`cp_resume`, `sdma_v5_2_start` and
`amdgpu_ib_ring_tests` order; `Report::queues` is set only when all pass and
failures are reported as `Error::Queues`.
`ColdBoot::prepare_media(doorbells)` reserves the VCN/JPEG owner after the
queues for the firmware set's unharvested VCN mask (nothing when both are
harvested); `Firmware::harvest_vcn(mask)` applies the mask first. The media
stages fail the boot only on device loss or revoked authority; every other
error is printed as `degraded` and the owner retained in `Report::media`.
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

Success returns `Report { reset: Option<reset::Report>, smu: Versions, gfx: GfxBootStatus, power: Option<Info>,
power_status: Option<PowerStatus>, media_firmware: MediaFirmware,
memory_aperture: Option<Aperture>, sdma: Option<Proof>, dmub: Option<Status>,
interrupts: Option<amdgpu_ih_navi22::Status>, media: Option<amdgpu_vcn_navi22::Status> }`;
`power` is populated only when the prepared table was uploaded. The session must
stay alive, or `take_psp()` can transfer its live ring/TMR owner to subsequent
GPU initialization after full success; that changes state to `Released` and
prevents a second transfer/run. `gfx_boot_status()` exposes the retained last
GC sample before transfer, including on failure. These observations do not set
`AmdGpu::fw_loaded`. Display-aware memory/link DPM, OS thermal interrupts,
general GPU mappings/queues, media submission and real-card validation remain
separate work.

`ColdBoot::dmub_hpd`, `dmub_aux` and `dmub_notification` expose the typed runtime
operations only after `FirmwareReady` and while PSP/TMR remains retained.
They refuse access after `take_psp()`. `dmub_hpd`/`dmub_aux` additionally
return `Dmub(Unsupported)` unless `allow_dmub_aux()` was called and the running
firmware answered QUERY_FEATURE_CAPS: Linux never routes DCN3.0 AUX/HPD through
DMUB (`dc_is_dmub_outbox_supported` is false outside DCN3.1 DPIA/GC11 unless
`enable_dmub_aux_for_legacy_ddc`), and `dmub_feature_caps` has no AUX bit.

### Navi 22 DCN3.0 mode math

`amdgpu_dml30::plan_joint(&[Stream], &Soc) -> Result<JointPlan, Error>` is the
DCN3.0 admission of a whole context (one to six streams, one unscaled linear
RGB plane each; GPUVM/HostVM, DCC, dynamic metadata, writeback and MPC combine
off): `dml30_ModeSupportAndSystemConfigurationFull`'s ODM choice per stream
(`Odm::TwoToOne` when one pipe's DISPCLK exceeds the DFS-rounded ceiling or a
DSC line is wider than 5184; 4:1, odd widths and more than six pipes are
refused), ROB and vertical-active bandwidth support (60% SDP / 40% DRAM), then
`display_mode_vba_30.c`'s performance calculation across every plane — one
DISPCLK and one DPPCLK DFS step (each plane its 1/255 DPPCLK share), the summed
read bandwidth, deep-sleep DCFCLK over all planes, extra latency per active
DPP, one VStartup search (each plane capped at its own MaxVStartupLines), the
multi-plane DRAM clock change margin (SynchronizedVBlank false: no OTG sync)
and stutter critical plane, one watermark set, DSC delay (`dscceComputeDelay`)
and ODM after-scaler allowance — and `display_rq_dlg_calc_30.c` per pipe (an
ODM slice's viewport, swath and blank end). `Stream { config, dsc:
Option<Dsc { slices, bits_per_pixel_x16 }>, phy_khz }` (`Stream::tmds(config)`
for 8-bpc TMDS); `JointPlan { prefetch_mode, clocks, watermarks, hubbub,
dram_clock_change, urgent_bandwidth_thousandths, planes: Vec<PlanePlan { odm,
geometry, prefetch, dppclk_khz, dsc_delay, pipes: [Option<PipePlan {
viewport_x, viewport_width, registers, cursor }>; 2] }> }`. The prefetch-mode
policy is `dcn30_internal_validate_bw`'s: mode 0, then mode 1 when mode 0 fails
or leaves the DRAM clock change unsupported; never mode 2. Without p-state
support the set A p-state watermark is 0 (`dcn30_fpu_calculate_wm_and_dlg`).
A top DCFCLK below `dcn3_0_soc.min_dcfclk` (500 MHz) is refused.
`plan(&Config, &Soc) -> Result<Plan, Error>` is the one-stream, one-pipe form
(`Plan { prefetch_mode, geometry, clocks, watermarks, prefetch, registers:
amdgpu_dml_regs::Registers, hubbub: WatermarkSet, dram_clock_change,
urgent_bandwidth_thousandths, cursor }`; a stream needing ODM is
`Unsupported` there). `dcn3_0_ip` / `dcn3_0_soc` constants (184 KiB DET per
pipe, 84 PTE requests, 191-cycle ping, 404 us p-state, 15.5/20 us self refresh,
fabric-adjusted urgent latency) in `amdgpu_dml::Fx` fixed point. Register
fields are Linux's `(unsigned int)` truncations and are refused (not wrapped)
when they exceed the DCN3.0 mask; everything fails before hardware is touched.

`Soc::from_board(levels, channels, width, dchub_refclk)` builds the top
bounding-box state from the DAL DPM table (DCFCLK doubling as fabric clock,
`memclk*16`, DENTIST-reachable DISP/DPP ceilings, PHY ceiling, VCO).
It defaults `Soc::dcn_revision` to 0. `Soc::for_gpu(gpu)` selects revision
0/2/3 from an exact discrete RDNA2 profile before admission; other values
are rejected. This selects resource limits and the corresponding latency
and DPTE parameters for DCN 3.0, 3.0.2 or 3.0.3.
`Soc::states(memory_mhz) -> Vec<Soc>` lists one state per lower UCLK level
ascending, then the top one (deviation: every state keeps the top DCFCLK,
where Linux pairs each UCLK with `dcn_bw_get_optimal_dcfclk_fclk_for_uclk`'s);
`plan_joint_lowest(&[Stream], &[Soc]) -> Result<(usize, JointPlan), Error>`
is `dcn30_internal_validate_bw`'s voltage-level search: the lowest supporting
state and its plan.
`amdgpu_dcn_inventory::vram_channels(vbios)` reads `vram_info` v2.5 module 0
(`channel_num`, `(1 << channel_width) / 8` bytes) as `get_vram_info_v25` does;
other revisions are refused.

`unsafe amdgpu_dcn30_hubbub::Hubbub::new(gpu, pci_cap)` owns the DCN3.0
arbiter. `dchub_refclk_khz(dccg_ref)` mirrors `hubbub2_get_dchub_ref_freq`
but refuses a disabled global timer or a reference outside 40–60 MHz.
`unsafe program(&WatermarkSet, refclk)` (no HUBP fetching) writes sets A–D
identically (data/VM-row urgency, trip to memory, SR enter/exit, DRAM clock
change, FRAC_URG_BW nom/flip), `ARB_SAT_LEVEL = 60 * refclk_mhz`,
`MIN_REQ_OUTSTAND = 0x1ff`, forces self refresh off, and reads every write
back; values wider than their DCN3.0 field are refused rather than masked.

### Navi 22 multi-stream contexts, ODM, DSC and DP MST

`amdgpu_navi22_modeset::Resources` is the DCN3.0 pool for several streams:
`acquire_stream(connector, timing, Odm, dsc) -> Lease { route, odm_pipe, dsc }`
takes the next pipe, its preferred frontend, a PHY PLL shared with an
identical synchronizable HDMI timing (`resource_find_used_clk_src_for_sharing`,
`resource_are_streams_timing_synchronizable`; refcounted, freed by its last
sharer) or the DP DTO, the ODM secondary pipe from the top of the pool
(`dcn30_find_split_pipe`) and DSC n for pipe n; `release_stream(&Lease)`.
`admit(requests, extras, states, vco) -> (Vec<StreamPlan>, JointPlan, Soc)`
chooses each `Request { link, connector, sink, want, mst }` stream (HDMI by
`select_hdmi`, DP SST within its verified link by `dp_link::decide_link_settings`
/ `bandwidth_kbps`, with DSC (`amdgpu_dcn30_dsc::select`) when the
uncompressed stream does not fit and the sink has DSC and FEC, MST slots
within one link) and plans them jointly at the lowest supporting state.
`unsafe Group::new(gpu, cap, &[Request])`, `unsafe enable(power, pool,
tables, board, links, aux: impl Links, draw(k, y, row)) -> Vec<Output>` and
`disable(tables, aux)` light the context as `dc_commit_state`:
`dcn30_init_hw` and the clocks/watermarks once, per stream
`dcn20_enable_stream_timing` (ODM 2:1 by `optc3_set_odm_combine` after the
timing), `link_set_dpms_on` (HDMI; DP SST; DP SST with DSC: engines, encoder
and OPTC config, FEC-ready training through
`amdgpu_dcn30_dp_link::train_with_retries_fec`, FEC on, DPCD 0x160, PPS on
VPG generic 11..14; DP MST: the shared link trained once in MST mode, the
stream's SAT row, ACT, ALLOCATE_PAYLOAD and VC rate), then every front end
under its OTG lock (`hubp.select_vtg`, an ODM slice's viewport at its offset).
`leases()`, `plans()`, `joint()`, `members()`, `state() -> GroupState`.
Pipeline additions: `set_odm_combine`, `set_odm_bypass`,
`mpc_rate_control_off`; `Hubp::{program_at, select_vtg}`.

`amdgpu_dcn30_dsc` is the DCN2.0 DSC block as DCN3.0 instantiates it:
`select(timing, dsc_caps, fec_caps, link_kbps) -> Option<DscConfig>`
(`compute_config_dcn20`: the 1188/1200 MHz encoder rules), `plan(timing,
cfg, odm) -> Plan { config, picture, engine, odm }`, `engine_values`, and
`Dsc::{power, start, stop, optc, encoder, pps, fec_ready, fec_enable}`
(`dsc2_set_config`/`dsc2_enable`, `dccg` DSC forward, `DOMAIN16+n` power
gating, `enc3_dp_set_dsc_config`, `optc3_set_dsc_config`,
`enc3_dp_set_dsc_pps_info_packet`, `enc2_fec_set_ready/enable`);
`sink_caps(aux)` reads DPCD 0x60 and 0x90. `amdgpu_dcn30_dp_link`'s
`Source::fec_ready` (default no-op) and `train_with_retries_fec(.., fec)`
add `dp_set_fec_ready` (DPCD 0x120) to the shared training.

`amdgpu_dcn30_mst` is DCN3.0's 8b/10b MST source: `Source::{allocation(
transmitter, &[Allocation]), vc_rate(fe, (x, y))}`
(`dcn10_link_encoder_update_mst_stream_allocation_table`,
`enc1_stream_encoder_set_throttled_vcp_size`), `NativeAux`, `Link { start,
add, remove, edid, stop }` over the shared `dp_mst_mgr` sideband manager,
`budget(pixel_khz, link_kbps) -> Option<(pbn, slots, vc)>` and
`link_kbps(rate, lanes, fec)`; DIG and VBIOS transmitter mode 5 (DP_MST).

### Navi 22 VBIOS display command tables

DCN3.0 sets `dmub_command_table` (`dcn30_resource.c`), so while DMUB runs
`command_table2.c` sends these tables to DMCUB. `amdgpu_navi22_bios::Tables::new(vbios)`
validates the image; `.with_dmub(Some(&route))`, where
`DmubRoute::new(Option<&mut Dmub>)` is `Some` only for a running DMUB with an
idle mailbox (`Dmub::vbios_ready`), routes every call through the `VbiosDmub`
trait to `Dmub::execute_vbios(VbiosCommand, payload)`: one `DMUB_CMD__VBIOS`
(128) inbox command with sub-type `DigxEncoderControl` (0, 12-byte payload),
`Dig1TransmitterControl` (1, 60), `SetPixelClock` (2, 16) or
`EnableDispPowerGating` (3, 4), executed synchronously and bounded by 100 ms
(`dc_wake_and_execute_dmub_cmd(WAIT)`); a timeout fails the mailbox and the
call (`Error::Dmub`). On the DMUB path table revisions are not checked
(the `*_fallback` helpers also go to DMUB); DIG1TransmitterControl uses the
v1.6 struct for a revision-6 table and the v1.7 data otherwise. Without
DMUB the tables run on the ATOM interpreter (logged), with
`amdgpu_atomfirmware_allocate_fb_scratch`'s FB scratch size and the bus's
`now_ms` driving atom.c's 20 s loop guard.
`pipe_power_gating(bus, pipe, Init|Disable|Enable)`
(EnableDispPowerGating v2.1), `set_pixel_clock(bus, &PixelClock { otg, pll,
transmitter, pixel_100hz, deep_color })` (v1.7, combo PHY PLL, UNIPHY encoder
object, HDMI mode, XTALIN reference; `pixclk_100hz` is the deep-colour-scaled
`actual_pix_clk_100hz` verbatim and `deep_color_ratio` the
`transmitter_color_depth_to_atom` code), `hdmi_stream_setup(bus, dig, pixel_khz)`
(DIGxEncoderControl v1.5 STREAM_SETUP) and `transmitter(bus, &Transmitter)`
(DIG1TransmitterControl v1.6/1.7, as `dcn10_link_encoder_enable_tmds_output`)
fill the `atomfirmware.h` blocks exactly as `command_table2.c` does; the ATOM
path refuses other table revisions. `Bus` (BAR5 dword `Mmio`, bounded by the
mapping) carries register access, DELAY and `now_ms`; an out-of-window access
or port I/O fails the table with `Error::Bus`. The interpreter ends a table at
an undecodable opcode or out-of-table jump and resumes after a bad SWITCH case
(atom.c), counting each as an `Anomaly`.

`amdgpu_atom_vm` now follows `atom.c` when `AtomState::bios`/`data_table` are
bound: `SET_DATA_BLOCK` takes absolute offsets from the master data table (255
selects the table start), ID operands read the image, every table execution
(including each CALLTABLE callee) gets its own zeroed WS from its header
(`ResolvedTable::ws_dwords`), and DELAY opcodes call `AtomState::delay_us`.
Unbound, the synthetic-table behaviour is unchanged.
The VM is generic over `Hooks<'a>` (`reg_read`/`reg_write`, `pll_*`/`mc_*`
defaulting to zero as SOC15 `cail_*`, `resolve`, `table_absent`, `delay_us`,
`now_ms`); `AtomState<'a, H = Closures<'a>>` derefs to its hooks, so the
closure fields keep working. `Machine::start(state, id, ps)` /
`Machine::from_bytes` + `Machine::step(state) -> Step::{Continue, Delay(us),
Done}` execute one opcode at a time with an explicit CALLTABLE stack, so async
callers sleep between opcodes; `execute_table`/`execute_bytes` drive it
synchronously. IIO (`ATOM_IIO_*`, indexed from data table 23 like
`atom_index_iio`; read program `port`, write program `0x80|port`) is executed;
sub-dword destinations keep the raw saved bits; SHL/SHR shift the raw value;
MUL32/DIV32 are 64-bit; a CALLTABLE to a zero directory entry is a no-op. PS/WS/FB
range, PCI/SYSIO and undefined-IIO cases continue as in Linux and are counted in
`AtomState::anomalies`/`first_anomaly`; the same-jump stuck guard is 20 s by
`now_ms` (65 536 repeats / 1 000 000 opcodes without a clock).

### Navi 22 native HDMI and DP SST scanout (opt-in)

`unsafe amdgpu_dcn30_hdmi::Hdmi::new(gpu, pci_cap, dig, transmitter)` owns one
DIG frontend/VPG and backend in Linux's split: `connect_to_otg(otg)`
(`enc1_dig_connect_to_otg`), `setup(DigMode)` (`dcn10_link_encoder_setup`),
`setup_stereo_sync(otg)`, `connect_be_to_fe(bool)` (one-hot FE source,
others kept), `stream_attribute(khz)` (RGB, 8 bpc, no scrambling — refused at
or above 340 MHz), `info_packets(&avi)`, `stop_info_packets()`,
`set_avmute(bool)` and the no-op `audio_infoframe` hook.
`amdgpu_dcn30_dp::{Link, Stream}` are the DIO DP halves (`enc1_configure_encoder`,
TPS1–4, passthrough/video idle, `link_encoder_disable`; MSA, VSC SDP via VPG,
`enc2_stream_encoder_dp_unblank` M/N and stream enable,
`enc1_stream_encoder_dp_blank`); `dp::Aux` is the sink transport
(`amdgpu_navi22_display::DisplayAux` over native AUX). VBIOS
`Transmitter { action, transmitter, mode, lanes, hpd, connector, symbol_khz }`
marshals v1.6/v1.7 (SETUP_VSEMPH via `Tables::transmitter_lane`, HPO 0).

HDMI 2.0 on DCN3.0 (m5hdmi): `hdmi::stream_for(edid, &timing, max_bpc,
limited, Limits { hdmi6g, max_phy_khz }) -> Option<Stream>` chooses amdgpu_dm's
format (4:2:0-only modes as 4:2:0; else RGB at the deepest declared depth up to
`amdgpu.max_bpc`, 2-bpc step-down; else 4:2:0-also) against
`dcn10_link_encoder_validate_hdmi_output` (600 MHz, HDMI_6GB_EN from
`amdgpu_dcn_inventory::encoder_caps`) and DML30's `min(600, PHYCLK)`.
`Stream { format: Format { depth, ycbcr420, limited }, pixel_khz,
character_100hz, character_khz, scramble: Scramble::{Off, LowRate, Above340},
scdc, avi, vendor }` carries the halved TMDS pixel clock, `phy_pix_clk`, the
scrambling decision (> 340 MHz, or LTE_340Mcsc) and the AVI/HDMI-VIC vendor
InfoFrames. `write_scdc_data(ddc, &stream)` (Sink/Source_Version, TMDS_Config
0/1/3; fails only a scrambled stream), `read_scdc_data` and
`write_scdc_legacy(ddc, scdc_present)` (disable/unplug, best effort) speak SCDC
over `dp::Aux::scdc_read/scdc_write` (default: unsupported;
`DisplayAux` implements them on the HDMI connector's I2C engine at 0x54).
`Hdmi::hdmi_stream_attribute(&stream)` programs depth/scrambler/1/4 clock rate,
`hdmi_info_packets(&stream)` sends AVI (packet 0) and vendor (packet 1) in
Linux's order; a VPG conflict that never clears is logged, not fatal.
`unsafe hdmi::Formatter::new(gpu, cap, pipe)` owns the pipe's FMT (dynamic
expansion, SPATIAL8/10 dither, full-range clamp, 4:2:0 subsampling), OTG 4:2:0
container (OPTC_DATA_FORMAT, H_TIMING_DIV_MODE), MPC OCSC (sRGB / sRGB limited /
YCbCr709, coefficient set A) and DPG black. `Pipeline::hdmi_output()` exposes
the admitted stream to the unplug path.

`amdgpu_navi22_modeset::Resources::acquire(&connector)` is the DCN3.0 pool:
first free pipe, the preferred DIG FE (= transmitter) or else the last free
one, `dc_resource_find_first_free_pll` for TMDS, the DP DTO for DP.
`choose(&reports)` picks a connected HDMI sink, else the first DP sink with
EDID and DPCD. `unsafe Pipeline::new(gpu, pci_cap, connector, route)` claims
the route's pipe and DIG plus the DAL clock owner and HUBBUB; `unsafe
enable(power, pool, tables, Board, links, sink, aux, draw)` runs
`dcn30_init_hw` (dccg2_init, golden init, VGA off) and the GOP takeover
(`amdgpu_dcn30_takeover`: `enc3_hw_init`, plane power gating, `dcn10_init_pipes`,
`dce110_power_down`; pipe 5 never power gated), then the DAL clocks and mode,
prepare_bandwidth (clocks then watermarks), `dcn20_enable_stream_timing`
(OPTC/OTG clock enable with bounded waits, SetPixelClock + PHYPLL resync or
DP DTO phase/modulo, timing, OPP black, `enable_crtc`, one frame),
`link_set_dpms_on` (HDMI: setup, STREAM_SETUP, attributes, AVI, transmitter
ENABLE, setup, BE→FE, AVI, AVMUTE off; DP: setup, MSA/VSC, PHYCLK floor,
BE→FE, `amdgpu_dcn30_dp_link::train_with_retries` at the least verified link
carrying the mode, setup, unblank; see "Navi 22 DP link layer"),
then the front end under `optc3_lock` and a two-frame underflow watch.
`Output` carries the route, trained `DpLink` and `Inherited` GOP state.
Failure records `State::Failed { step, error }` and undoes only started steps
(no zero-clock SetPixelClock); cancellation keeps `State::At(step)` and
`disable(tables, aux)` retires it. `check_underflow()` turns an OTG/HUBP
underflow black and sets `State::Quarantined`. `ColdBoot::modeset_hdmi()`
detects, `choose`s, acquires a route and lights with `test_pattern`.
The pipeline budgets DCN30's one 256-wide 32-bpp cursor in DML30 as
`dcn20_populate_dml_pipes_from_context` does (`Config::cursors` ≤ 1: CNVC
cursor DPPCLK delay, cursor bandwidth and urgent burst in the prefetch and
urgent-fraction checks, `Plan::cursor` = `calculate_ttu_cursor`) and programs
`DCN_CUR0_TTU_CNTL0/1` with the HUBP. After the front end latches it starts
the stream's audio through `amdgpu_dcn30_audio::Audio::start_for_sink`
(`ClockManager` implements `AzaliaWake` with DALSMC 0x11); teardown stops it
first; audio errors are logged and never fail the display.
Kernel-test builds route every display owner's `amdgpu_reg_window::Window`
through one attachable register model (`amdgpu_navi22_modeset_model`).

### Navi 22 HDMI and DP audio

`unsafe amdgpu_dcn30_audio::Audio::new(gpu, pci_cap)` owns the DCCG audio DTO
(DCN base index 1), every Azalia endpoint and function-parameter register,
and the audio fields of each DIG's AFMT/HDMI/DP_SEC block (base index 2). The
HD-Audio function (1002:ab28, `narf_audio::hda`, ATI codec 0x1002aa01) is a
separate owner. `unsafe start(AudioStream, AudioInfo, &mut impl AzaliaWake)`
and `unsafe start_for_sink(stream, edid, wake)` (ELD fields from
`amdgpu_navi48_boot::sink_audio_info`; `Ok(None)` without audio) run after
unblank on a stream whose OTG runs with the DIG routed to it, and refuse a
stream whose samples or DP audio packets are already on. They run
`dce_aud_hw_init` and the endpoint scan once, `find_first_free_audio`,
`dce110_setup_audio_dto` (lowest HDMI pipe: DTO0 from its pixel clock; DP
only: DTO1 from the 730 MHz DPREFCLK with 512 Fs), `enc3_se_hdmi_audio_setup`
(AFMT, ACR N/CTS at 8 bpc) or `enc3_se_dp_audio_setup`, `dce_aud_az_configure`
(HDMI blanking rate filter; none for DP SST 8b/10b), the HDMI Audio InfoFrame
on line 2, `AzaliaWake::wake_azalia` (Linux's `dcn3_enable_pme_wa`,
`DALSMC_MSG_BacoAudioD3PME`), `dce_aud_az_enable`, the DP secondary audio
packets, unmute and a readback check. `stop(dig, wake)` runs before blank:
mute, AFMT clock and DP audio packets off (the DP master enable stays while
video packets need it), the PME workaround, the HDMI Audio InfoFrame off and
`dce_aud_az_disable`; every step runs and the first error is returned.
`record(dig)` reports `Record { stream, audio: DisplayAudio, state }`; a
failure or cancelled start is retained (`Failed { step, error }` /
`Programming(step)`) with its endpoint, never replayed, and only `stop`
releases it.

### Navi 22 native presentation and KMS

Pipeline hooks: `request(Option<Timing>)` makes `enable` light exactly that
timing (`select_wanted`: it must be in `offered`, else `NoMode` before any
write); `admitted()` is the retained `Admitted { soc, refclk_khz, plan,
offered }` (`offered(sink, soc, vco)`: every distinct EDID timing inside the
TMDS ceiling that DML30 admits); `scanout_address()`/`scanout_mapping()`;
`unsafe release_scanout()` returns the activation surface after a successful
`disable`.

`unsafe amdgpu_dcn30_flip::Flip::new(gpu, pci_cap, pipe)` owns a pipe's
HUBPREQ flip/address/interrupt and OTG status registers (DCN base index 2):
`program(addr)` is `hubp3_program_surface_flip_and_addr` (VSYNC flip, VMID 0,
stereo/TMZ off, low address last; 48-bit, 256-byte aligned), `pending()` is
`hubp2_is_flip_pending` (FLIP_PENDING or EARLIEST_INUSE != requested),
`wait(timeout_us, wake)` polls it to completion or `Timeout` (the flip stays
armed), `set_interrupt`/`ack(Interrupt::{Flip, Vupdate, Vblank})` are
`irq_service_dcn30`'s SURFACE_FLIP_INT_MASK/CLEAR and
OTG_GLOBAL_SYNC_STATUS VUPDATE_NO_LOCK/VSTARTUP enable/clear, and
`position()` samples OTG_STATUS_POSITION with a stable 24-bit frame count.
`unsafe amdgpu_dcn30_cursor::Cursor::new(gpu, pci_cap, pipe)`:
`show(addr, (w, h), at, viewport, (refclk, pixclk))` programs
`hubp2_cursor_set_attributes` + `dpp3_set_cursor_attributes` (premultiplied
ARGB, 256-pixel pitch, no degamma) and the position under
`mpc1_cursor_lock` (CUR_VUPDATE_LOCK_SET, base index 3); `move_to`, `hide`.
`placement` follows amdgpu_dm `get_cursor_position` and
`hubp2_cursor_set_position` (negative origin into the hotspot, 256x256 cap).

`unsafe amdgpu_navi22_scanout::Scanout::new(gpu, pci_cap, pipe, front, map,
timing, refclk)` adopts the lit surface as buffer 0: `prepare_back(pool,
flush)` reserves/clears/publishes buffer 1, `upload_back(x, y, row)` writes
it, `flip(flush)` HDP-flushes, arms and waits up to `flip_timeout_us` (four
frames + 20 ms, at least 50 ms) for EARLIEST_INUSE, then swaps roles;
failure enters `State::Failed` with both buffers reserved.
`enable_interrupts(ih)` subscribes to `source::{pflip, vupdate}(pipe)` and
then enables them; vectors only shorten the wait. `set_cursor`,
`move_cursor`, `hide_cursor`, `position()`, `stop()` and `unsafe release()`.

DCN30 KMS publication shares connector/CRTC bookkeeping with DCN401, but
publishes only linear XRGB8888/ARGB8888 primary planes and the generic cursor
ABI. It clears the shared helper's GFX12 modifiers, overlays and native plane
geometry, and provides a LINEAR-only `IN_FORMATS` blob. Publication selects
the same PCI-identified RDNA2 card as the submission backend.

`Card::addfb2_bo` accepts those linear GEM framebuffers on a native atomic
amdgpu card without GFX12 capabilities. Nonlinear modifiers, DCC and other
formats are rejected. The async KMS entry resolves synthetic-primary targets
as well as native-plane targets, prepares their VRAM placement outside the
KMS lock, and revalidates master and targets before commit. TEST_ONLY prepares
no placement and publishes no state. Atomic, SETCRTC and PAGE_FLIP preserve
the pinned GEM source through the presentation handoff.

The DCN30 presenter waits for implicit WRITE fences before taking the GPU
owner. CPU-visible placements are copied by bounded rows, honoring pitch and
offset; hidden VRAM uses the existing SDMA transfer into private system
staging, also outside the owner. The frame retains its `ScanoutPin` through
queueing, readback, copying and the completed native back-buffer flip.
Unsupported format/extent checks precede queueing. GEM sources never fall
through to a raw physical pointer. This is a copy presenter, not direct
scanout of client buffers; secondary CRTCs still cannot present.

`ColdBoot::{modeset_display(connector, sink, want, draw), stop_display(),
display_scanout(), display_admitted(), display_output(),
prepare_display_back_buffer(), flip_display(), set_display_cursor()}` own
these. `into_recovery` re-prepares DMUB and the display owner from the
retained VBIOS/routes so the recovered sequence restarts DMUB.

`amdgpu_navi22_kms` holds DRM state: `MAX_CRTCS` (4, the shared id scheme's
outputs) CRTCs — CRTC 0 (pipe 0, id 1) the single-pipe owner's, CRTCs 1..3
(`Kms::secondary`) lit only together with it as one multi-stream context —
and one connector per board route (ids per `amdgpu_navi48_kms`); connectors offer
the DML30-admitted timings (`Kms::reconcile_sinks(reports, offered)`), a DP
sink's bounded by its verified link (`modeset::offered_on(sink, soc, vco,
verified)`, `dp_validate_mode_timing`; the receiver-caps ceiling until
verified). Automatic routing takes an HDMI sink first, else the first DP one, for
CRTC 0; with `set_auto_multi(true)` (fb: the `amdgpu.navi22_multi` flag) each
remaining lightable connector takes the next free secondary CRTC, otherwise
only DRM routes them. Every connector may drive every CRTC
(`possible_crtcs`); routing a connector steals it from another CRTC.
`crtc_at(d)`, `crtc_of(connector)`, `targets()`, `published_at(d)`,
`offered_at`/`find_mode_at`, and `next_group(running) -> GroupAction {
Nothing, Unlight, Light(Vec<(crtc, connector, want)>) }` (a context is wanted
while a secondary CRTC wants a sink; any change relights it whole; a failed
attempt waits for the next request, `attempted_group`).
`request_display_{active,route,mode}`, `request_connector_crtc`,
`display_offers` (TEST_ONLY/SETCRTC validation), `restore_displays`, `publish`
apply to any CRTC. `display_admission(admitted, streams)` (`DisplayAdmission`:
DML30 DRAM clock change; `watermarks` the HUBBUB half — sets A-D programmed
from the plan — which power saving ANDs with its PMFW table upload;
stutter/FCLK/deep sleep false). `amdgpu_native_kms`
dispatches the DRM bridges to Navi22 once it published, else Navi48.
`amdgpu_navi22_platform::{modeset_displays(draw), spawn_display_monitor(),
flip_display(), set_display_cursor(), set_hw_cursor(), present_frame(),
native_present_ready(), crtc_vblank(), vblank_time(), display_admission(),
relight_after_recovery()}`: only CRTC 0 presents and has vblank. Each
monitor pass first converges the multi-stream context (`converge_group`):
the single pipe is torn down, then every wanted CRTC lights through
`ColdBoot::modeset_group(requests, draw)` (stopped by `stop_group()`;
`group_outputs()`, `group()`, `flush_group_scanout()`), the console follows
stream 0, the other scanouts are static, and `display_admission` reports the
context's lowest-state plan; when the context fails CRTC 0 lights alone.
Publication withdraws the console and drains
`scanout_access` before any teardown; recovery withdraws and stops the pipe
before reset and the monitor relights once `recoveries()` increments. The fb
handoff calls `modeset_displays` and the monitor unless
`amdgpu.native_display=0` (the hardware cursor is on unless
`amdgpu.rdna2_hw_cursor=0`; display detection runs with native display or
`amdgpu.display_probe`).

### Navi 22 DP link layer, hot-plug and link loss

`amdgpu_dcn30_dp_link` is Linux DC's 8b/10b SST link policy for the DIO,
driving `dp::Aux` (now with `set_timeout_us`, `connected` and `delay_us`
defaults) and a `Source` (`dp::DioSource { link, phy }`: enable_dp_output,
training patterns, video idle, common-level SETUP_VSEMPH per lane,
disable_output). `retrieve_caps(aux, VbiosLttpr)` is `retrieve_link_cap`:
LTTPR timeout (3.2 ms), `dp_retrieve_lttpr_cap` on VBIOS-LTTPR-aware boards
(`VbiosLttpr::from_vbios`: DCE_INFO display_caps 0x40 aware / 0x20
non-transparent, `amdgpu_dcn_inventory::lttpr_caps`), else
`wake_up_aux_channel`; transparent mode and the echoed count for a chain;
receiver caps with 20 post-OUI retries; the 552 us timeout without a chain;
extended caps and the DPRX feature list. `Caps::{max_link, eq_pattern}` are
`dp_get_max_link_cap` (HBR3 x4 encoder; a DPCD 1.4 chain bounds it) and
`decide_eq_training_pattern` (TPS4/TPS3/TPS2 by sink support only). The LTTPR
mode is `dp_decide_8b_10b_lttpr_mode` (not aware: none). Training is
`dp_perform_link_training`: exit, LTTPR mode (non-transparent reads each
repeater's interval), channel coding, link settings (0.5% downspread,
enhanced framing, POST_LT_ADJ_REQ_GRANTED below TPS4), hop-by-hop repeaters
(farthest first, TPS4, `repeater_training_done`, source drive only for the
hop next to it), CR (5 same-swing / 100 total, max-VS stop) and EQ (6 tries,
CR-lost partial/full), adjust requests as `dp_decide_lane_settings`
(maximized, PE capped by VS), then `dp_transition_to_video_idle` (5 ms and
`dp_check_link_loss_status`, or `perform_post_lt_adj_req_sequence`).
`train_with_retries` is a commit's `perform_link_training_with_retries`
(4 attempts at one setting, no fallback, +50 ms delays);
`verify_link_cap` is `dp_verify_link_cap_with_retries` (2 rounds) with
`decide_fallback` (`decide_fallback_link_setting`: CR → rate first, EQ →
lanes first); `decide_link_settings` and `mode_fits` are
`decide_dp_link_settings` / `dp_validate_mode_timing`; `handle_hpd_rx_irq`
is the SST part of `dp_handle_hpd_rx_irq` (`RxEvent::{None, AutomatedTest,
LinkLoss}`; ESI block from DPCD 1.4; loss only with the sink in D0). AUX
transport failures abort and disable the source; FEC, the source OUI, eDP,
DPIA and fixed-VS paths are not implemented.

`Pipeline` for DP: `set_lttpr_policy`, `assume_link_cap(Option<DpLink>)`
(skip verification for a sink verified before with the same caps),
`link_cap()`, `dp_caps()`; `enable` retrieves caps and verifies the link
after `init_hw` and the clock start (`ClockManager::link_rate_floor`), then
selects with `select_dp_on` against it. `check_dp_link(aux)`,
`retrain(tables, aux)` (`dp_handle_link_loss`: audio, blank, link off,
same-setting training, unblank; the front end keeps scanning out; failure
leaves `At(Step::Link)` for `disable`) and `disable_unplugged(tables, ddc)` (no
DPCD transaction; an HDMI SCDC sink still gets `link_set_dpms_off`'s
unchecked legacy TMDS_Config write via `hdmi::write_scdc_legacy`; resumes an
interrupted stop). `amdgpu_navi22_display::Display`
retains each connector's verified link keyed by its receiver caps
(`verified_link`, `set_verified_link`), and adds `hpd_sense(index)` and
`aux_timeout(index, us)`. `ColdBoot::{display_hpd_senses(),
forget_display_link(i), display_link_cap(i, dpcd), check_display_link(),
retrain_display(), stop_unplugged_display()}` serve the platform display
monitor, which each pass (1 s, or woken by HPD/HPD-RX vectors): tears the lit
display down without AUX when its HPD falls (connector disconnected),
re-detects every connector when any HPD changes or pulses (EDID inventory of
dark connectors; a pulsed lit sink is stopped and relit), checks the lit DP
link and retrains on loss, stopping it to relight from a fresh verification
if retraining fails; then converges KMS as before.

### Navi 22 native AUX, DDC and HPD

`unsafe amdgpu_dcn30_ddc::Ddc::new(gpu, pci_cap, crystal_khz)` claims all six DCN3.0 AUX
engines and DDC pads, the shared hardware I2C engine and all six HPD blocks
(Navi22 profile only; DCN base index 2 bounded to `DC_GPIO_AUX_CTRL_5`, base
index 1 to `MICROSECOND_TIME_BASE_DIV`). `bind(line, hpd, Signal)` performs the
AUX half of `enc3_hw_init` (`AUX_DPHY_RX_CONTROL0` 0x103d1110, TX 0x21c7a,
`AUX_HPD_SEL`, quarter receive window), a 552 us AUX timeout, opens the HPD pin
in interrupt mode, enables `DC_HPD_EN` if firmware left it clear and programs
`program_hpd_filter` delays (HDMI 500/100 ms, DP 80/0 ms); a DP line without
HPD is refused. `hpd`/`hpd_raw` read `DC_HPD_SENSE_DELAYED`/`DC_HPD_SENSE`;
`hpd_ack` mirrors `hpd0_ack` (ack, then arm the opposite polarity);
`hpd_rx_ack`/`hpd_interrupt` program the IH-facing bits. `aux(line, AuxRequest)`
is `dce_aux_transfer_with_retries` over `dce_aux_transfer_raw` (7 attempts, DEFER
budget, 3 timeouts, 2 invalid replies, ACKM status polling, NACK/HPD-loss
terminal); `dpcd_read`/`dpcd_write` bound payloads to 16 bytes. `i2c(line, Mode,
messages)` is `link_query_ddc_data`: I2C-over-AUX in 16-byte MOT chunks, or one
hardware I2C command (`dcn2_i2c_hw_construct`: 538-byte buffer, setup limit 3,
100 kHz from `MICROSECOND_TIME_BASE_DIV`, or from the VBIOS crystal
(`dce_refclk_10khz`) when a reset DCN has not been through `dccg2_init`;
≤256 bytes per message). Pads are
opened/closed exactly as `dal_ddc_open`/`dal_ddc_close` per transaction.
DMCU/hardware-owned engines return `Engine`; every wait is bounded; a dropped
future releases arbitration and restores pads synchronously; an all-ones read
returns `DeviceGone` and leaves the owner `Failed`.

`amdgpu_navi22_display::Display` binds every HDMI/DP VBIOS path (DDC line and
HPD from the record list/GPIO LUT; a shared line or HPD is refused) and
`detect(index)`/`detect_all()` return `Disconnected`, `Connected(Sink { edid,
preferred, hdmi, dpcd })` or per-connector `Failed(error)`: HPD first, the 16-byte
DPCD receiver capability field for DP, then a checksummed EDID (base plus up to
four extensions, E-DDC segment pointer past block 1, four tries per block) over
I2C-over-AUX or the hardware I2C engine. Only owner loss fails the whole probe.
`Firmware::prepare_display(gpu)` decodes routes before device I/O and
`ColdBoot::prepare_display()` claims the owner without I/O; both are optional
for firmware bring-up. `ColdBoot::detect_displays().await` requires
`FirmwareReady` (as does `ColdBoot::detect_display(index).await`, one
connector's sink read, which the monitor uses for the long-pulse
`same_edid` check that keeps an unchanged lit stream), and `amdgpu_navi22_platform::detect_displays().await`
serializes it through the retained owner. The framebuffer boot handoff logs one
line per connector after a successful firmware run; detection reads sinks only. `dmub_mailbox_state()` also reports failed
or cancelled transport attempts without accessing hardware.

HPD over the IH ring: `Display::arm_hpd_interrupts()` is `amdgpu_dm_hpd_init`
over DCN3.0's irq service (every HPD/HPD_RX source acked and disabled, then
HPD on per wired connector and HPD_RX on for DP; `hpd0_ack` re-arms the
opposite polarity), `hpd_event(instance, rx)` is `dc_interrupt_ack` and
returns the connector index. `ColdBoot::arm_display_hpd()` subscribes to
`amdgpu_ih_navi22::source::DCN_HPD` before arming and returns the
subscription; `ColdBoot::display_hpd(Hpd)` acknowledges one vector.
`amdgpu_navi22_display::serve_hpd(sub, ack)` drives them and bumps
`HOTPLUG` (`version`, `notify`, `wait(&mut since, period_ms)` with a 50 ms
floor), and the platform's runtime services spawn it and wake the display
monitor; without an IH ring polling runs alone. A freshly enabled HPD block
is polled up to 1 s for its connect filter before detection reports
`Disconnected`.

### Navi 22 boot ownership and framebuffer handoff

`amdgpu_navi22_platform::start_fault_service().await` runs once after a
successful boot: it subscribes to `VMC_FAULT` and `UTCL2_FAULT`, then unmasks
the GMC fault interrupts and spawns one task per source that attributes each
entry through `Gmc::handle_fault` under the owner lock. The first 16 faults
are logged; `fault_count()` counts all of them. The framebuffer handoff calls
it; a failure only logs, and faults then stay masked (default-page redirect).

`amdgpu_navi22_platform::prepare(physical_boot_framebuffer)` is an unsafe,
single-CPU boot-only entry. It requires a posted physical GPU, permanent probe
mappings, no NARF VRAM allocations/queues, and stopped CPU framebuffer writers.
On x86_64 it calibrates the TSC duration scale before preparing or claiming the
GPU, and returns `Error::Clock` without device writes when no source is
available. This initcall precedes frame's normal HPET/timer-IRQ setup; firmware
minimum delays and deadlines must not use the uncalibrated identity scale.
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

`narf-fb` registers `amdgpu-discrete-firmware` during Subsys, appending it after
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

### Shared client GPU virtual memory (GMC 10–12)

`amdgpu_vm` holds the client address-space geometry and entry encoding for
every GMC generation; `amdgpu_vmhub_regs` holds the per-hub VMID registers
and TLB invalidation. Both are shared by the Phoenix, Navi 22 and Navi 48
paths; only the tables differ.

- `Geometry::{GMC11, GMC12}`: GMC 12 (GC 12.0.x) walks GMC 11's four-level,
  48-bit layout (`amdgpu_vm_adjust_size(256 * 1024, 9, 3, 48)`) and differs
  in `format`. `VmState::with_geometry` builds an address space for a
  generation; `VmState::new` remains GMC 11. Each DRM open takes
  `VmState::for_card(index)`: GMC 12 for a Navi4x card (by
  `drm_registry::pci_id` and `amdgpu::family_for_pci_id`), GMC 11's layout
  and encoding — which GMC 10 shares — for every other card.
- `PteFormat::{Nv10, Gfx12}` encodes entries as `gmc_v1x_0_get_vm_pte`:
  GMC 12 puts MTYPE at 55:54 (NC/UC only), PRT at 56 with IS_PTE, PDE_PTE at
  63 and the block fragment size at 62:58, sets DCC for `GFX12_DCC` buffers
  and forces UC only for `UNCACHED` ones (GMC 10/11 also for the coherent
  flags). Fresh and emptied directories use the format's PDE_PTE pattern.
  `pte_flags` remains GMC 11's entry point.
- `VmHubRegs` per hub: `GFXHUB_V3_0`/`MMHUB_V3_0` (Phoenix),
  `GFXHUB_V2_3`/`MMHUB_V2_3`, and `GFXHUB_V12_0`/`MMHUB_V4_1`
  (`regs_for(Family::Navi4, ..)`). `cntl_shift` moves CONTEXT_CNTL's block
  size, retry and fault-enable fields up one bit on GC 12 / MMHUB 4.1.
- `write_invalidate_tlb` issues `gmc_v*_0_flush_vm_hub` on the kernel's
  engine 17 at each hub's `eng_distance`, with Linux's request word
  (`invalidate_req`: VMID mask 15:0, FLUSH_TYPE 18:16, L2/L1 invalidates
  23:19). Hubs with `semaphore` (MMHUB) acquire the engine semaphore first
  and release it after the ACK, also on timeout (`TlbInvalidateError::{
  Semaphore, Timeout}`). The firmware-issued invalidate Linux uses once
  KIQ/MES runs is not implemented.

- Placement (`amdgpu_gem`): a card may register a `VramHeap` (its owned
  pool plus `fb_base`/`fb_offset`); `GemState::for_card` opens then place
  VRAM-allowed buffers there, zeroed through the BAR, with entries carrying
  `address - fb_base + fb_offset` and neither SYSTEM nor SNOOPED
  (`base_flags(false)` is VALID only, as `amdgpu_ttm_tt_pte_flags`). GTT
  buffers, VRAM|GTT ones when the heap is full, and every buffer on a card
  without a heap are buddy pages (SYSTEM|SNOOPED, identity IOMMU): the
  binary decomposition of the page count into buddy blocks (a block the
  allocator lacks is split in two), so a buffer may exceed one 32 MiB
  block and is never rounded up, charged against `gtt_limit()` (half of
  RAM, TTM's default; `gtt_used()` is the charge) and refused `NoSpace`
  past it; discardable VRAM-only buffers refuse `NoSpace` when their
  allowed domains exclude GTT.
  `GemObject::placement()` returns an `Arc<GemPlacement>` address lease.
  Its `phys`, `gpu`, `system`, `gpu_at(offset)` and `frames` describe the
  backing until the lease is dropped. GEM_VA retains the exact lease while
  constructing PTEs and throughout their lifetime. The object's
  `phys()`, `gpu()` and `system()` accessors give diagnostic snapshots,
  not a lifetime guarantee for raw addresses. `AMDGPU_INFO_MEMORY`
  and `VRAM_GTT` report that limit as the GTT heap, with its usage.
  `vram_heap_usage(card)` gives a registered heap's `HeapUsage { visible,
  unmapped }` as (size, used) bytes (`Pool::size` / `available`). On an
  open whose card has a heap (Navi 22 still answers its own),
  `AMDGPU_INFO_MEMORY` reports total VRAM as the hardware's, usable VRAM as
  the heap (visible + unmapped; the rest is the driver's, Linux's pinned
  and reserved VRAM), usage as its allocations, CPU-accessible usable as
  the visible pool with its usage, and each `max_allocation` as 3/4 of
  usable; `VRAM_GTT` reports the usable sizes. Without one, both report
  the hardware sizes as before.
  A heap may also carry an `UnmappedHeap` (an `UnmappedPool` past the BAR
  and a `VramClear` engine): a `NO_CPU_ACCESS` VRAM buffer goes there
  first, falling back to the visible heap. It is cleared by
  `VramClear::clear(fb-aperture address, bytes)` — clears complete in
  queue order, and a refused clear fails the create — whose fence becomes
  the buffer's KERNEL reservation fence. Such a buffer has `phys` 0 and
  `cpu_visible()` false: `frames`, `mmap_frames`, `load_u64`/`store_u64`
  refuse it. `GEM_MMAP` of any `NO_CPU_ACCESS` buffer is EPERM
  (`OperationNotPermitted`), as amdgpu_gem_mmap_ioctl. `GEM_VA` MAP adds
  the buffer's unsignalled KERNEL fences to its space
  (`VmState::depend_on`), and `AMDGPU_CS` waits for the space's
  `VmState::kernel_fences()` before queueing.
  On Navi48 the heap's `VramTransfer` (`amdgpu_navi48_platform` transfer
  mover) migrates these buffers: SDMA0 `COPY_LINEAR` kernel jobs move each
  chunk through a private 1 MiB CPU-mapped window of the driver's pool,
  queued in the same FIFO as clears so no copy overtakes an earlier clear.
  A copy travels alone in its job; an upload stages its chunk under the
  platform owner just before queueing, followed by an HDP flush, so a
  copy requeued by an SDMA0 reset re-stages. Each queued/inflight request
  independently retains its source/destination, GEM identity and window
  (`Arc<Stage>`), and its fence is added to the buffer's KERNEL reservation.
  A refused, timed-out (5 s) or lost-generation chunk fails the move with
  the original placement/PTEs intact; requests that hardware may still
  reach retain their backing. A generic lost-device fence wakeup does not
  prove a copy landed: migration returns `NoDevice`, and unreadable generic
  clear/copy fences stay pending until a real completed sequence or explicit
  retirement. CS propagates uncertain transfer/hardware errors before user
  queue publication rather than treating them as allocation fallback.
  Upload rechecks the live owner/generation after its final chunk/yield
  before returning. Completion waits retire proven inflight leases under
  the platform owner before placement commit, with backing drops outside
  the state spinlock. The independent queue task also collects its final
  inflight requests after a waiter is cancelled; bounded sleeps release the
  owner, and unreadable progress keeps collecting without inferring stop.
  The clearer records the owner generation. Under the same owner mutex
  that excludes reset/power transitions, it validates that generation and
  its live progress reader before CPU staging, then stages/flushes and
  submits without an intervening await. Old-generation queues cannot
  write their window or invoke stale progress MMIO. They refuse only
  unsubmitted requests; inflight leases stay retained. Quiesce withdraws
  the mover after suspend's eviction and reader invalidation, retaining
  the old queue in `ResetClearer` until a completed whole-device reset
  proves its DMA stopped. That proof explicitly retires the queue's shared
  queued/inflight state and marks its fences failed even if stale callers
  retain another queue clone; backing drops run outside its state spinlock.
  Failed/cancelled reset quarantines that queue alongside its device owner;
  registry removal cannot free its inflight resources. This applies even
  with the whole VRAM BAR-visible.
  Whole-device recovery and suspend acquire the card's live placement
  admission before the platform owner, so no reset can interleave the final
  upload validation with the coordinator's synchronous backing/PTE commit.
  Suspend closes admission before draining submitted jobs and evicting,
  and carries the same guard through quiesce, parked S3/BACO and resume.
  The guard stays held through fresh-owner publication. Abandonment before
  a full-reset proof quarantines it; abandonment after proof may release
  it but marks that card terminal either way. Fallible client admission
  wakes existing waiters with `NoDevice` and refuses new ones; CS checks
  terminal loss during its pre-admission dependency waits too. A temporary
  suspend does not mark loss. Gate acquisition never awaits under the
  platform owner, including suspend's failed-retirement recovery path.
  GFX12 DCC buffers (AMDGPU_GEM_CREATE_GFX12_DCC on a card registered by
  `amdgpu_gem::set_gfx12_dcc`: VRAM holds them compressed) never move by
  CPU copy (`amdgpu_gem::moves_by_engine`): `GemObject::relocate` and the
  CPU-mapping move refuse them (Busy), and `amdgpu_vm::relocate` (evict_all,
  reclaim_vram_locked, prepare_scanout) moves them from any VRAM, visible or past
  the BAR, through the card's transfer engine with
  amdgpu_ttm_copy_mem_to_mem's copy flags (`amdgpu_gem::ttm_copy_flags`):
  READ_DECOMPRESSED out of VRAM, WRITE_COMPRESSED with the buffer's tiling
  flags' GFX12_DCC max compressed block, number type, data format and
  write-compress disable into it, carried by `Work::Copy` to SDMA0's DCC
  word (the stage stands in for the GTT side, so it takes neither flag).
  The platform registers that mover (`amdgpu_gem::register_vram_transfer`)
  whether or not the card has VRAM past the BAR, and it stays registered
  through suspend's eviction with the heap withdrawn; quiesce then removes
  it, and a successfully restarted owner publishes a fresh mover. Without
  an engine, or for a CPU-mapped
  DCC buffer (whose mapping would have to follow a frozen CPU copy), the
  move fails and the buffer stays; suspend then fails cleanly (Busy) rather
  than corrupt it. Deviation: Linux unmaps a CPU-mapped buffer and moves it
  anyway (the next fault maps the new placement).
- Foreign PRIME import on an amdgpu card (`amdgpu_gem_prime_import` with
  `dma_buf_dynamic_attach`): another card's GTT amdgpu buffer or any card's
  KMS dumb buffer becomes a GTT-only buffer over the exporter's RAM pages
  (`GemState::import_foreign`), holding the exporter's placement or dumb
  lease and sharing its reservation for implicit sync; it never moves.
  Another card's VRAM (PCIe peer-to-peer) and other exporters are EINVAL.
  A buffer of the same card stays the same object.
- `GEM_USERPTR` (`amdgpu_gem_userptr_ioctl`): page-aligned non-empty
  ranges and known flags (else EINVAL); a writable range needs REGISTER
  (EACCES); ANONONLY refuses file-backed, shared and SysV ranges (EPERM).
  Every page is faulted in with a guarded user read, COW-resolved when
  writable (`AddressSpace::user_page_writable_or_resolve`) and pinned
  (`pin_user_page`) at creation, VALIDATE or not. The buffer is GTT-only,
  its entries follow each pin, READONLY maps without WRITEABLE (internal
  `BO_GPU_READONLY`, masked from GEM_OP), and GEM_MMAP, PRIME export and
  placement moves refuse it, as Linux does. LINUX-GAP: no MMU interval
  notifier, so the pins are a snapshot: later CPU remaps, fork-COW splits or
  munmap leave the GPU on the pinned frames (never freed memory).
- PRT (`GEM_VA` with `AMDGPU_VM_PAGE_PRT`): MAP/REPLACE record a range
  with no buffer (the handle is not looked up, as amdgpu_gem_va_ioctl maps
  it through `prt_va`) whose entries carry PRT without VALID; REPLACE with
  a buffer commits pages into it and REPLACE with PRT decommits them;
  UNMAP/CLEAR drop it. `VmState::mapped_object` is None there. This is
  what RADV's sparse binding and radeonsi's sparse buffers use.
- PRIME (`drm_devfs_bridge::AmdgpuDmaBufFile`): `PRIME_HANDLE_TO_FD` on an
  amdgpu card or render open exports a GEM buffer as a dma-buf that holds
  it (pages outlive every handle while the fd or a mapping of it lives),
  maps its frames (`GemObject::frames`) and answers `dma_buf_ioctl` against
  the buffer's one shared reservation (`GemObject::dma_buf`).
  `PRIME_FD_TO_HANDLE` on an open of the same card imports it as the handle
  that open already has for the buffer or a new one (`GemState::import`);
  another card's buffer is EINVAL (no foreign dma-buf attach yet). A
  `VM_ALWAYS_VALID` buffer is not exported (EPERM, as
  amdgpu_gem_prime_export): it belongs to its open's address space.
- Metadata (`amdgpu_gem`, `GEM_METADATA`): each `GemObject` keeps its
  tiling flags and an opaque blob of at most 256 bytes with its flags, so
  every handle to the buffer sees what its exporter set (SET; an empty blob
  clears the blob and keeps its flags) and GET returns them, leaving the
  rest of `data` as passed. Unknown ops succeed doing nothing and unknown
  handles are ENOENT, as amdgpu_gem_metadata_ioctl. `GemObject::load_u64` /
  `store_u64` read and write 8 bytes through the kernel's own mapping.
- Lifetimes: each VA mapping record holds its buffer (`Arc<GemObject>`, as
  `amdgpu_bo_va` holds its BO) and its `Arc<GemPlacement>` address lease, so `GEM_CLOSE` cannot free pages the tables
  still point at; a CPU mapping holds it too (`GemState::mapping_object`,
  the card and render nodes' `mmap_lifetime`), as a VMA holds its object. CLEAR and REPLACE split partly covered mappings
  (`amdgpu_vm_bo_clear_mappings`): the remainders keep their records,
  offsets and entries; only the covered range's entries are cleared.
  Once a job ran in an address space (`VmState::note_job`), what it drops —
  removed records' buffers, emptied page tables, and the whole space when
  its file closes — waits in the card's deferred list
  (`amdgpu_cs::defer_until`) until the card's submitter reports that job
  complete (`amdgpu_cs::retire`); before any job, frees are immediate.

- Submission (`amdgpu_cs`): a card registers a `Submitter`
  (`register_submitter`); on such a card the `/dev/dri` ioctl route
  (`dispatch_async`, for card and render nodes) queues a validated
  `AMDGPU_CS` and returns the engine's sequence as the handle, and
  `AMDGPU_WAIT_CS` parks until it completes or the client's absolute
  monotonic deadline passes (status 0/1; a negative s64 deadline waits
  forever, `amdgpu_gem_timeout`). Every `drm_amdgpu_fence`-shaped handle
  (WAIT_CS, WAIT_FENCES, FENCE_TO_HANDLE, DEPENDENCIES) resolves through
  `amdgpu_ctx_get_fence`'s rules: the context must be the open's and the
  IP/ring one the engine runs (EINVAL), 0 is signalled, `!0` the ring's last
  job, a handle of another ring or past the ring's last emitted job EINVAL.
  `AMDGPU_GEM_WAIT_IDLE` waits for the buffer's reservation fences, and for
  the open's last jobs (`VmState::last_jobs`) only on a `VM_ALWAYS_VALID`
  buffer (Linux's shared root reservation); unknown handles ENOENT.
  `dispatch_async(card, cmd, arg, &CsOpen { vm, gem, ctx, syncobjs,
  bo_lists, files })` also answers `AMDGPU_WAIT_FENCES` (all/any, count 0
  EINVAL, all stops at the first timeout, any reports `first_signaled`,
  `!0` on timeout) and `AMDGPU_FENCE_TO_HANDLE` (GET_SYNCOBJ,
  GET_SYNCOBJ_FD, GET_SYNC_FILE_FD through `files`; other `what` EINVAL),
  with or without a registered submitter. CS chunks: `SYNCOBJ_IN`/`OUT`,
  `SYNCOBJ_TIMELINE_WAIT`/`SIGNAL` (`Submission::{in,out}_syncobjs` of
  `SyncobjPoint { handle, flags, point }`; one post-dependency chunk; an
  unknown out-syncobj EINVAL, in-syncobj ENOENT, no fence/point EINVAL or,
  with WAIT_FOR_SUBMIT, waited up to 5 s then ETIME), `BO_HANDLES` or a
  `bo_list_handle` (not both, EINVAL; unknown list ENOENT), `FENCE`,
  `DEPENDENCIES`/`SCHEDULED_DEPENDENCIES`. In-fences and dependencies are
  waited for before queueing — the ioctl waits, where Linux's scheduler
  would hold the job. Out points get the job's `JobFence`
  (`SyncObjCore::add_point` for a non-zero point, the payload otherwise).
  Implicit sync (amdgpu_cs_sync_rings / amdgpu_cs_submit): before queueing,
  the ioctl waits for every unsignalled fence on the reservation of each
  listed BO and of the user-fence BO, except fences of the open's own
  address space (`DrmFence::owner` == `VmState::owner`,
  `AMDGPU_SYNC_NE_OWNER`); on `EXPLICIT_SYNC` buffers only KERNEL fences
  are waited for; the job
  then becomes each of those BOs' WRITE fence. A BO the job does not list
  gets no fence, as in Linux.
- `amdgpu_bo_list`: `dispatch(cmd, arg, &BoListTable, &GemState)` is
  `DRM_IOCTL_AMDGPU_BO_LIST` (CREATE / UPDATE / DESTROY, entries read as
  `amdgpu_bo_create_list_entry_array` reads them, > 128 Ki EINVAL, unknown
  BO ENOENT, UPDATE of an unknown list ENOENT, DESTROY of one succeeds);
  `read_entries` is shared with the BO_HANDLES chunk.
- DRM syncobjs (`drm::syncobj`, `drm::syncobj_ioctl`): a handle names a
  shared `SyncObjCore` whose payload is a fence or a `FenceChain`
  (`dma_fence_chain`, with `find_seqno` / `query_point` and walk-time
  collection); `FenceArray` and the `to_drm_leaves` / `from_drm_leaves`
  adapters bridge to sync_file leaves. `syncobj_ioctl::dispatch(nr, arg,
  table, timeline, ctx)` (user opens; array waits park through
  `IoctlContext::restart_after`) and `dispatch_sync` (kernel callers, no fd
  ioctls, 15 s cap) serve CREATE, DESTROY, HANDLE_TO_FD / FD_TO_HANDLE
  (opaque `SyncobjFile` fds and EXPORT/IMPORT_SYNC_FILE), WAIT, RESET,
  SIGNAL and, when `timeline` (amdgpu; EOPNOTSUPP otherwise),
  TIMELINE_WAIT, QUERY, TRANSFER, TIMELINE_SIGNAL and EVENTFD, with
  `drm_syncobj.c`'s errnos. amdgpu reports `DRM_CAP_SYNCOBJ_TIMELINE` = 1
  (`drm_ioctl_bridge::amdgpu_cap_value` / `amdgpu_get_cap`). Without a submitter, CS parses and is refused as before
  and GEM_WAIT_IDLE reports idle. `pm4::Pm4Builder::vm_flush` builds the in-ring VM flush
  (shared by GMC 11 and 12).

Jobs are named by tickets: the CS handle, opaque to clients, with the ring
index in its high 32 bits (`Submitter::ring_for` maps an IP/ring to it).
An address space keeps its last ticket per ring (`VmState::last_jobs`); a
deferred free waits for all of them, and GEM_WAIT_IDLE for each.
Dependencies must name a ring the engine serves and a handle of that ring.
A `FENCE` chunk (`Submission::user_fence`: handle, offset) names a
one-page GEM buffer of the open with the 8 bytes at `offset` inside it
(EINVAL otherwise, as amdgpu_cs_p1_user_fence); the job's handle is stored
there by the CPU when a fence read retires the job (`GemMapping` retains
the exact placement through `defer_until`), never replacing a newer handle of the same ring.

Timeouts (`amdgpu_ring_watch`): `Submitter::submit` takes the submitting
context's `amdgpu_ctx::Health`. A `RingWatch` per ring follows its jobs;
the front job's timeout (`JOB_TIMEOUT_NS`, amdgpu's 2 s lockup default)
counts from when it reached the front, and past it the ring is hung: that
job's `Submitter::error` is `TimedOut` and its context guilty. The ring
refuses new jobs (`Canceled`) and freezes memory retirement. Later jobs in
healthy contexts remain pending for replay; jobs in a guilty/canceled context
are skipped with `Canceled` after reset. Error completion wakes waiters but
never alone releases buffers, page tables or VMIDs. `RingWatch` retains each
job descriptor, context health, logical ticket and its hardware fence.
Logical tickets skip zero on 32-bit wrap, preserving the CS ABI's zero/no-job
handle; physical hardware sequences still wrap through zero independently.
GC12/SDMA7/VCN5 client fence readers check live authority, HDP visibility and
device presence before and after the fence sample, then revalidate authority.
A legitimate all-ones physical sequence remains valid; an absent BAR does
not. A failed sample in the current platform generation synchronously marks
the device lost and cancels/freezes every ledger before waking waiters. It
never retires memory. An old-generation reader reports an error without
touching hardware or poisoning the replacement generation.
`AMDGPU_WAIT_CS` of an ended job with an error fails with it
(amdgpu_cs_wait_ioctl); `AMDGPU_CS` on a context with an error fails with
it before queueing (amdgpu_ctx_get_entity); `CTX QUERY_STATE2` reports
RESET, plus GUILTY for `TimedOut`, and `QUERY_STATE` `UNKNOWN_RESET`. The
Navi48 platform spawns a watchdog that checks its rings every 100 ms while
its submitter stays registered. A hung graphics ring is recovered as
gfx_v12_0_reset_kgq: `Mes::reset_kernel_queue(queue, vmid)` sends MES12
RESET (`amdgpu_mes12::reset_kernel_queue`: `reset_legacy_gfx` with the
HQD's pipe, queue, VMID, MQD, doorbell and write pointer; other queues by
doorbell with `reset_queue_only`), then `Queues::submit_fence` queues a
fence-only slot as the ring test, which needs a free slot and must land
within 100 ms (`ColdBoot::recover_client_ring`). Only then does
the platform re-emits healthy jobs, forcing VM flush, PASID mapping and
context reload, and binds their original tickets to the new hardware fences.
`RingWatch::recovered` reopens retirement only after every replay is published.
The test fence permits retirement of skipped jobs only; innocent jobs keep
all memory until their translated replay fence passes. Errors survive later
resets. Cancellation or failed replay leaves the ledger frozen. A hung compute ring is recovered as gfx_v12_0_reset_kcq
(amdgpu_gfx_reset_mes_compute; GFX12 resets MEC queues by MMIO):
`Mes::prepare_compute_reset` first attempts MES12 SUSPEND
(`amdgpu_mes12::suspend_all`), then
`Queues::reset_compute_hqd` (RLC safe mode when RLC is enabled, with a
100 ms acknowledgement deadline; with the compute queue selected in
GRBM_GFX_CNTL, CP_HQD_DEQUEUE_REQUEST 2 and SPI_COMPUTE_QUEUE_RESET 1, then
CP_HQD_ACTIVE polled idle for up to 100 ms; the prior selection restored).
If the HQD stays active, the RS64 path of
mes_v12_0_reset_compute_pipe_mmio asserts CP_MEC_RS64_CNTL.MEC_PIPE0_RESET,
clears CP_HQD_ACTIVE and CP_HQD_DEQUEUE_REQUEST on all four MEC1 pipe-0
HQDs while reset is asserted, reselects queue 0 and deasserts reset. Other
MEC control bits are preserved. An unexpectedly active sibling or an
already asserted pipe reset refuses the fallback before writes. Reset
assertion, HQD clearing and deassertion are read back; an uncertain clear
leaves the pipe held in reset. No await occurs during the pulse. RLC safe
mode is exited on returned success/error; cancellation retains it and
`State::ResettingCompute`, refusing replay, submission and restore. Returned
failure records `Failed`; success records `ComputeReset`, permitting only
the subsequent restore once MES has unmapped the queue. Reset alone neither
advances a fence nor releases memory. The sequence continues with
`Mes::unmap_reset_queue` (REMOVE_QUEUE with `remove_queue_after_reset` on
scheduler firmware 0x5a+, `amdgpu_mes12::unmap_reset_kernel_queue`),
`Queues::restore` (the descriptor as first built, a ring of
PACKET3(NOP, 0x3fff), read and write pointers 0) and
`Mes::map_bootstrap_queue`; `Mes::all_gangs(false)` (RESUME,
`resume_all`) is attempted on every returned path and must succeed before the
same ring test closes recovery. A fully drained firmware rejection of SUSPEND
runs MES detect-only against an independently initialized report area. Only
an empty report or this owner's exact compute doorbell/pipe/HQD permits MMIO;
a foreign queue refuses recovery, a malformed report fails MES, and timeout
or cancellation leaves MES quarantined without submitting another command. A hung SDMA0 ring is recovered as
sdma_v7_0_reset_queue (`ColdBoot::recover_client_sdma`):
`Sdma::reset_ring` writes SDMA0_QUEUE_RESET_REQ bit 0 and waits up to 100
ms for the engine to clear it, then programs the ring as
sdma_v7_0_gfx_resume_instance(restore) with both pointers and their
writebacks at the software write pointer, so the engine resumes past every
queued slot; `Sdma::submit_fence` is the ring test. Before the test,
`recover_client_sdma`'s `skipped` hook learns the sequence the engine
completed, and the platform puts every VRAM clear its ring held past it
back at the front of the clear queue, unsignalled (`ClearState::requeue`),
so a clear's fence never reads complete off the test's fence. Innocent
client jobs use the same logical-ticket replay as GC12. VRAM clear fences
follow SDMA0's hardware fence only, never a timeout's verdict.

`unsafe amdgpu_navi48_platform::recover().await` is whole-device recovery
after ring recovery fails. Its caller must stop every kernel CPU VRAM/GOP
writer and exclude external PCI/firmware owners. As for RX 6000 (Linux
`amdgpu.gpu_recovery` on a dGPU), `unsafe set_automatic_recovery(bool)`
(enabled by the fb boot handoff unless `amdgpu.gpu_recovery=0`) lets the
watchdog start it after a failed ring reset or a terminal fault (RAS fatal error,
lost interrupts, refused coordinated recovery) or after the display monitor
stops with a quarantined display owner, once per submitter
generation and at most `MAX_AUTOMATIC_RECOVERIES` (3) times per boot, since
each recovery quarantines the old owners' VRAM. `set_recovery_console_hook`
pauses kernel boot-framebuffer writers for the reset; a lost device leaves
them paused. User CPU mappings of VRAM are not revoked, as in Linux.

System suspend (S3) uses the async system-PM phase
(`unsafe register_system_pm()`, installed by the fb boot handoff).
`prepare_suspend` follows amdgpu_pmops_suspend for a dGPU. An exclusive
presentation gate drains queued frames, pending GEM cursor commits and local
presenter/cursor tasks (including their WRITE-fence waits) before any display
or heap changes. Admission/requeue checks the gate under its mailbox lock;
a drain that cannot finish within five seconds refuses with `Busy`. The last
shown CPU cursor image remains available for replay. Kernel framebuffer
writers are paused before their surfaces are withdrawn. Under OWNER, the
display monitor generation is invalidated and every retained stream stops
through the native teardown journal (`retire_suspend_displays`), with client
pins retired only after fetch stops. The zero-stream bandwidth release then
lowers the clock floors. `ColdBoot::prepare_suspend` defensively refuses a
retained stream or unfinished teardown. A failed teardown recovers before
refusing; eviction/preflight refusal republishes the heap and restarts the
monitor. Then suspend unregisters
the client VRAM heap and evicts every client VRAM buffer to system memory
(`amdgpu_gem::evict_all`, as ttm_resource_manager_evict_all, widening each
buffer's allowed domains with GTT for the move and waiting for its jobs;
a buffer still pinned stays in VRAM, as it is not on TTM's LRU; the card is
an LRU card, `amdgpu_gem::set_lru_eviction` from `publish_client_vram`, so
this walk, like pressure's `evict_visible_locked` and `reclaim_vram_locked`, covers
every live buffer of the card, `CARD_OBJECTS`, including one only a
framebuffer holds after CREATE_DUMB, ADDFB2 and closing the handle; other
cards keep walking their opens' handle tables),
then quiesces exactly as recovery does and saves PCI state with bus mastering cleared
(`Reset::save_for_resume`). A refused eviction or preflight leaves the
device running; a failed PCI save recovers immediately with mode1.
`resume_from_suspend` (amdgpu_pmops_resume) restores PCI state before any
MMIO, waits for the bootloader, posts the cold card with ATOM ASIC_Init as
amdgpu_device_need_post decides (`Mode::Resume`, `Method::PowerCycle`;
mode1 + post when SOS survived), replays GDDR6 training and brings up a
fresh owner as recovery does, then restores the widened domains; buffers
stay in system memory until validation promotes them (a framebuffer's
buffer, a dumb one included, at its next commit's
`amdgpu_kms_async`). The interrupt-gated
device-PM handler accepts the native RX 9000 owner only while async prepare
holds it (`system_suspended()`). Suspend/resume transitions are serialized by
`PM_TRANSITION`. Their pinned retained future is polled inline, including by
sync bridges; cancellation transfers unfinished work to an executor cleanup
task. A canceled successful suspend resumes before releasing exclusion, and a
canceled resume retains the parked owner through completion. System-PM's
runtime reference follows the retained operation and rollback. Unsafe callers
must retain their external ownership exclusions through that cleanup; its
completion requires executor progress after cancellation. Hardware unvalidated.
A detached display can change the surviving configuration's Vmin ODM topology.
If `replan_displays` needs different pipes (`Admission(Pipes)`), the monitor
performs the retained full relight before publishing the survivor's plan;
it does not retain a joint admission naming the departed stream.
S3 (and runtime) resume start from a clean quiesce (`Mode::Resume`), so
`restart` drops that owner instead of quarantining it and returns the VRAM
it published to the driver pool (`amdgpu_vram::Pool::reclaim_retired`:
a dropped published reservation is retired, still excluded, until a
resume post proves no hardware can reach it). Recovery (`Mode::Recovery`)
keeps quarantining. The S3 prepare holds a runtime-PM reference and
resumes a runtime-suspended card first (device_prepare/device_complete).

Runtime PM (`amdgpu_navi48_runtime_pm`, on `narf_power::runtime_pm` and
its PCI layer) follows amdgpu_drv.c:

```rust
pub enum Mode { None, Px, Boco, Baco, Bamaco }            // AMDGPU_RUNPM_*
pub struct Platform { pub external: bool, pub px: bool, pub boco: bool, pub passthrough: bool }
pub fn detect_mode(runpm: i32, support: u8, platform: Platform) -> Mode;
pub fn describe(runpm: i32, support: u8, mode: Mode, platform: Platform) -> &'static str;
pub fn parse_runpm(value: Option<&str>) -> i32;           // amdgpu.runpm, default -1
pub fn check_display(runpm: i32, lit: u8, connected: bool) -> Result<(), RpmError>;
pub fn baco_path(mode: Mode, audio_present: bool, audio_bound: bool) -> platform::Baco;
pub enum Audio { Absent, Unbound, Bound { d3: bool } }
pub unsafe async fn register(runpm: i32, console_on_gpu: bool) -> Option<Mode>;
pub async fn ioctl_enter(card: u32) -> Result<Option<RpmActiveRef>, FsError>;
pub fn on_open(card: u32);
pub fn displays_changed(lit: u8, connected: bool) -> DisplayDelta;
pub fn apply_display_refs(delta: DisplayDelta);
pub async fn system_prepare(); pub fn system_complete();
pub async fn access() -> Result<Option<RpmActiveRef>, boot::Error>;
pub fn device() -> Option<Arc<RuntimePmDevice>>; pub fn mode() -> Option<Mode>;

// amdgpu_navi48_platform
pub struct Baco { pub bamaco: bool, pub armd3: bool }
pub unsafe async fn runtime_suspend(baco: Baco) -> Result<(), boot::Error>;
pub unsafe async fn runtime_resume() -> Result<boot::Report, boot::Error>;
pub async fn bamaco_support() -> u8;
// amdgpu_smu_navi48::Smu
pub fn bamaco_support(&self) -> u8;                        // BACO_SUPPORT | MACO_SUPPORT
pub unsafe async fn baco_enter(&mut self, bamaco: bool, armd3: bool) -> Result<(), Error>;
pub unsafe async fn baco_exit(&mut self, armd3: bool) -> Result<bool, Error>;
// amdgpu_reset_navi22::Reset
pub unsafe fn clear_post_scratch(&mut self) -> Result<(), Error>;
```

`register` (fb boot handoff, after `register_system_pm`) runs
`amdgpu_device_detect_runtime_pm_mode` with `amdgpu.runpm` (-1/-2 auto,
0 off, 1 BACO, 2 BAMACO) and `amdgpu_device_supports_baco`
(smu_v14_0_get_bamaco_support: board platform_caps BACO/MACO, and PMFW's
BACO feature, now allowed at boot). NARF evaluates no AML, so neither PX
(ATPX) nor BOCO (`_PR3`) is available and auto selects BAMACO on a board
with MACO circuitry, else BACO. The PCI function is registered as probe
leaves it, with a 5000 ms autosuspend, `allow` and `put_autosuspend`.
References: every DRM ioctl on the card and render node
(amdgpu_drm_ioctl), an open queues a resume (devfs lookup is synchronous),
each lit CRTC (amdgpu_dm's commit tail, from `publish_outputs`), hwmon
power-cap and performance-level writes (amdgpu_pm_get_access), the S3
transition, and permanently a kernel console that draws into this GPU's
VRAM (boot framebuffer on the card or `amdgpu.native_display`) — the lit
fbcon display that keeps Linux's dGPU awake. The idle/suspend check refuses
while a CRTC is lit and, unless `runpm=-2`, while a sink is connected
(published by the display monitor, else scanned at suspend). Suspend
drains the rings (bounded at 10 s, else `Busy`), evicts client VRAM and
quiesces as S3 without pausing the console, saves PCI state, then
smu_v14_0_2_baco_enter: with the audio function enabled or absent
(smu_cmn_is_audio_func_enabled: a bound driver) ArmD3(BAMACO when the
board has MACO, else BACO) and PMFW powers down when the PCI layer writes
D3hot; otherwise EnterBaco(BACO_SEQ_BAMACO or BACO) and 10 ms. A bound
audio function that is not in D3 refuses (`Busy`): PMFW would keep the card
up and NARF cannot resume a card whose SOS survived without a reset. A
refused BACO entry restarts the card through the resume post and is a
sticky runtime-PM error. Resume (after the PCI layer's D0 and header
restore): ExitBaco plus BIOS_SCRATCH_6/7 = 0, or 10 ms and ArmD3(ULPS),
then the S3 restart: PCI restore, post as need_post decides, GDDR6
training replay and a fresh owner that skips the SMC load while PMFW stayed
resident (psp_load_smu_fw's in_runpm skip; a mode1 resume reloads it). VRAM
contents follow Linux: client buffers were evicted to system memory and
kernel owners are rebuilt. A failed resume loses the device; later ioctls
fail. Hardware unvalidated.
A finished GDDR6 trainer (`Ready`, `ResidentSos` or `Disabled`) moves to
the new owner, which replays it before SOS with `Trainer::resume`
(psp_v14_0_memory_training(PSP_MEM_TRAIN_RESUME): restore the cache to C2P
and short-train, escalating to P2C save and long training as Linux does;
NARF refuses to short-train from an unsigned cache). Preflight refuses a
trainer that failed or never finished. The platform
withdraws CS, client VRAM allocation, scanout and timestamps, drains CPU views,
stops the old IH service, and advances the lock-protected fence-reader
generation. Old fence readers and clear workers cannot access the new owner.
Failure/cancellation quarantines the retained owner and refuses another reset.

`amdgpu_reset_navi22::Reset::new_navi48_recovery` shares bounded PCI/ReBAR/MSI
save/restore and the ATOM interpreter with Navi22, using exact Navi48 banks.
SMU14 mode1 writes debug parameter 0, command 2 and response 0, then waits
one second without MMIO before restoring PCI decoding. PSP14 bootloader and
NBIO MEMSIZE waits are bounded. ASIC_Init requires command revision 2.1+,
normal engine/memory flags, 24-bit boot clocks and sixteen reserved dwords.
The fresh boot owner reruns firmware, GMC, IH, MES and ring proofs, then the
CPU interrupt proofs, before publishing submission again. Old published
firmware/display reservations stay quarantined; client heap allocators retain
live allocations. VRAM contents are lost and old contexts report reset; new
contexts are required for submission. The reset counter remains global as in
the existing Navi22 context-query implementation. Old tickets retain their
errors and numbering; new hardware sequences start independently. Late
memory deferrals are covered by the successor ledger. IH registrations gain
new generations. Power and previously enabled display monitoring restart with
new worker generations; the display monitor discards old modeset witnesses
before relighting. The firmware sequence is boxed and the by-value owner/result
payload is bounded in tests to leave stack space for recovery. Physical
reset/replay acceptance remains unverified.

The Navi48 platform registers both kernel queues as its card's submitter
after boot: up to eight IBs per submission (`Job::new`, in order in one
slot), all for the graphics ring or all for the compute ring
(`Queues::submit(Pipe, Job)`; the compute frame writes registers without
the PFP, skips PFP_SYNC_ME, flushes on invalidation engine 1 and marks IBs
`INDIRECT_BUFFER_VALID`), run on a GFX hub VMID from 1–7 with the
open's root page directory (`VmState::root_pde`, GMC 12 only), through
`amdgpu_gfx12_queue::Queues::submit` — one 256-dword ring slot of pipeline
sync (wait for the ring's previous fence) and VM flush (GFX hub, the ring's
engine, PFP_SYNC_ME) when the grant asks for a flush, the LUT write, an
ACQUIRE_MEM when the first IB carries `AMDGPU_IB_FLAG_EMIT_MEM_SYNC`
(`Job::mem_sync`; GCR_REQ on SDMA), an HDP request/ack handshake,
CONTEXT_CONTROL on the graphics ring
(state reloads when `Job::ctx_switch`: the ring's previous job came from
another `(owner, ctx_id)`, Linux's scheduler entity), IBs and an
interrupting RELEASE_MEM fence;
`Busy` when the 1024-dword ring is full. A job also maps its VMID to its
open's PASID in the IH VMID LUT (OSSSYS `IH_VMID_0_LUT + vmid`, after the
flush, as gmc_v12_0_emit_pasid_mapping), so a fault carries the client's
PASID; `VmState::pasid` allocates one per address space
(`amdgpu_vmid::PasidHandle`) and releases it through the deferred list.
Each job is noted on its address space and every fence read retires
completed jobs' deferred frees. The fault monitor charges each VM fault to
the IV's PASID (`amdgpu_vmid::record_fault`: address from the IV, the hub's
protection-fault status, GFX 0 / MM 1; a zero status never replaces a
useful one; faults for freed PASIDs are dropped), and
`AMDGPU_INFO_GPUVM_FAULT` (`amdgpu_info::dispatch_for`) answers from the
open's PASID. `AMDGPU_INFO` still reports acceleration unavailable, while
`HW_IP_INFO`'s `available_rings` reports bit 0 for each IP whose ring 0
the open's card's submitter serves (`amdgpu_info::available_rings`).

Every native GC12 client slot follows `gfx_v12_0_ring_emit_hdp_flush`
before CONTEXT_CONTROL and IB execution: WAIT_REG_MEM operation 1 writes
NBIO bank 2's HDP_FLUSH_REQ (0x106) and waits on HDP_FLUSH_DONE (0x107),
using CP0/PFP for graphics pipe 0 and CP2/ME for compute pipe 0. This is
independent of the grant's page-table flush and `Job::mem_sync`; neither
VMID reuse nor skipping ACQUIRE_MEM removes host-data visibility ordering.
The register banks are the same NBIF6.3.1/NBIO7.7 layouts already bounded
by queue construction. CPU publication and fence-read HDP flushes remain
part of their existing visibility contract.

GC12 additionally accepts one graphics+compute gang: IBs are grouped by
entity, in their original order within each entity, with at most eight IBs
per entity. The last IB's entity is the leader, as Linux
`amdgpu_cs_p1_ib`/`amdgpu_cs_job_idx` specify. Generic CS invokes
`Submitter::validate_submission` before dependency waits or BO placement;
Navi4 refuses unknown routes, oversized groups and SDMA/media mixed gangs.
The actual native submission repeats validation. DRM version and
ACCEL_WORKING remain unchanged; this is not a Mesa acceptance indication.

Under OWNER, `Queues::prepare_gang([Job; 2])` validates both GC12 frames
and both rings' free capacity without writing ring storage, WPTR or a
doorbell. It returns a private `PreparedGang` tied to that queue owner and
its exact cursor/sequence pair. Tentative cloned VMID-manager state grants
both jobs through the ordinary concurrent-flush/PASID rules, retaining
one client's identical root/PASID on both queues. Every watch receipt,
aggregate leader and both VM lifetime tickets are registered before the
first possible hardware publication. Error-bookkeeping capacity is also
reserved first. `publish_gang(prepared, leader)` stages both command slots
and flushes them before either WPTR, then releases follower before leader
without an intervening await or other queue publisher. WPTR polling counts
as possible publication even if its doorbell/flush fails. A publication
error freezes both reserved cursor generations, stops all ledgers, returns
the accepted aggregate receipt for normal BO/syncobj attachment, and
requests whole-device recovery; uncertain resources remain pinned.

The public ticket names the leader's ring/sequence, but its completion
requires both physical constituent fences. Later tickets of the same
leader fence context also wait for its outstanding follower, preserving
syncobj/dma_resv context subsumption. VM/PTE/BO retirement uses this full
aggregate completion, never an error signal or only the leader's fence.
`Submitter::signalled` may wake API waiters with an error while hardware
still owns resources; `Submitter::retired` alone answers whether a backend
completion/reset witness permits freeing BOs or page tables. The default
requires a successful signalled fence; Navi4 independently checks physical
aggregate progress. Global deferred retirement during an unrelated BO's
relocation uses `retired`, so it cannot free an errored gang or other job
which that relocation did not itself wait for.
A timeout/fault while a gang is outstanding escalates to whole-device
recovery, rechecking under OWNER before any independent ring reset.
Gangs are never replayed. Stopping/resetting records cancellation for a
physically finished leader whose follower remains pending; successor
ledgers retain that error. Normal single-ring paths keep their existing
ring recovery. Physical gang scheduling/barrier/retirement acceptance is
still required; models check admission, order, completion and ownership.

`amdgpu_vmid::VmidManager` grants VMIDs as amdgpu_vmid_grab does with
concurrent flushes: `grab(GrabRequest { owner, pd_addr, tlb_seq, pasid,
ring }, done)` returns a `Grant { vmid, needs_flush, map_pasid }` or None
to wait. A submission needs some VMID with no unfinished job on any ring;
it then reuses the most recent VMID its own space (`VmState::owner`, a
never-reused identity) used at the same page directory, flushing only if
`VmState::tlb_seq` (bumped whenever a mapping is removed) passed that
VMID's last flush or that flush is pending on another ring, and otherwise
takes the idle VMID and flushes. The LUT entry is rewritten when the VMID
mapped another PASID or that write is pending on another ring. `commit`
records the job once the ring accepted it. Navi48 grants VMIDs 1–7 (8–15
are KFD's, first_kfd_vmid) and sets `Job::flush` / `Job::map_pasid`
from the grant.

SDMA0 runs client jobs as ring 2 (`AMDGPU_HW_IP_DMA`, instance 0, ring 0)
through `amdgpu_sdma_navi48::Sdma::submit(Job)`, after both SDMA proofs
(busy before). Its frame follows sdma_v7_0's ring functions in 256-dword
slots of the 1024-dword ring: when flushing, a memory POLL_REGMEM pipeline
sync and the GFX hub flush on invalidation engine 11 (REGISTER_WRITE /
POLL_REGMEM); the LUT write; an unconditional SDMA0 HDP_FLUSH POLL_REGMEM
(DONE then REQ byte addresses, bit 10, equal, retry 0xfff and interval 10);
INDIRECT packets NOP-aligned to end on 8
dwords, IBs 32-byte aligned with no CSA; and an uncached FENCE (no TRAP;
completion is polled through `FenceReader`). The ring is started with
`IB_ENABLE`, as sdma_v7_0_gfx_resume does.
`Sdma::submit_kernel(&[KernelOp])` queues kernel jobs on VMID0
(framebuffer-aperture) addresses in the same ring, sequence and fence:
`KernelOp::Fill` as sdma_v7_0_emit_fill_buffer (CONSTANT_FILL, COMPRESS,
dword fill; dword-aligned, a multiple of 4 bytes) and `KernelOp::Copy` as
sdma_v7_0_emit_copy_buffer (COPY_LINEAR with CPV and TMZ from its
`flags`, amdgpu_copy_buffer's `AMDGPU_COPY_FLAGS_*`; its last dword the
DCC word `copy_dcc_word`: SDMA_DCC_DATA_FORMAT / NUM_TYPE / READ_CM(2) /
WRITE_CM(1, or 2 with WRITE_COMPRESS_DISABLE) / MAX_COM / MAX_UCOM(1) with
READ_DECOMPRESSED or WRITE_COMPRESSED, else 0; non-overlapping), split
into 1 GiB packets; a job that overflows its 256-dword slot is refused.

`amdgpu_vcn_navi48::Vcn` owns Navi48's VCN5.0.0 instance 0 static-power
VCPU and unified ring on NBIF6.3.1. Unsafe `new` reserves separate owned
stack/context/shared/ring/fence backing and requires the matching permanent
pool, PSP TMR, MMHUB VMID0, BAR2 and exclusive media/NBIF/reset/PM ownership.
`start(MediaFirmware, PowerStatus).await` refuses active inherited rings,
a running VCPU, an occupied media doorbell range, and MM_DPM/DS_VCN policy.
It publishes backing before its first awaited write, powers ONO2..5 on,
programs PSP firmware, 128 KiB stack, 512 KiB context and a shared page,
then boots the VCPU with ten bounded reset retries. The shared record enables
the unified queue and dGPU SMU interface; byte queue-mode updates preserve
adjacent firmware-owned state. The owned NBIF range and 32-bit doorbell
follow Linux's SOC24 assignment. VCPU master interrupts remain masked during
the first transport proof.

`prove().await` emits a native unified FENCE/TRAP/END frame, padded to 64
dwords, and requires both its new fence and complete RPTR drain.
It proves queue transport only. `stop().await` sets DPG hold-off, drains the
ring, checks VCPU and LMI/UMC write-clean, then blocks/resets VCPU and LMI,
disables its doorbell/ring and proves posted writes completed before marking
backing reusable. Uncertain completion, revocation or cancellation retains
the published allocation and refuses replay until device recovery.

`unsafe Smu::set_vcn_power(bool).await` is SMU14's dGPU instance-0
PowerUpVcn/PowerDownVcn, with a fresh static-media/protection feature check.
Power-down requires the retained VCPU/LMI retirement proof. As other SMU
runtime operations, cancellation leaves the mailbox owner busy and terminal
transport errors forbid reuse. No display/GFX clock policy is changed.

`Vcn::prove_interrupts().await` requires a retained independent dispatch
owner (`Key::Vcn { instance: 0 }`, VMID0/PASID0) before enabling the VCPU
master source. It samples/drains old source-119 evidence, emits another
new-sequence frame, and requires its fence, full RPTR drain and exactly one
fresh VCN trap. A routed MSI also requires a fresh CPU interrupt; polling
routes report `InterruptProof::msi_verified = false`. Failed or cancelled
proofs retain source ownership and backing, refuse stop/replay and require
device recovery. VCN/JPEG diagnostics and foreign contexts cannot complete
the proof; media vectors only wake registered owners, never complete fences.
Both transport proofs also check the entire fence-page guard and CPU write
pointer, rejecting wider-than-dword or stray firmware writes.

The low-level `unsafe Vcn::submit(Job)` accepts up to eight owned client
IBs only after both proofs. Its 256-dword unified frame follows Linux's
`vcn_v2_0_enc_ring_emit_*` callbacks: MMHUB4.1 engine-0 semaphore/PTB/
invalidate/ACK/release and final PTB-low wait when flushing, the MMHUB
PASID LUT when remapping, an unconditional HDP-remap register write, IBs
under the lent MMHUB VMID, then a 32-bit kernel FENCE/TRAP/END and NOPs.
VCN has no separate mem-sync/context-control callbacks or user fence.
The caller retains the job's VMID, mappings and every reachable resource
until `completed_job`/`FenceReader` passes its returned physical sequence
or reset proves retirement. Fence readers check live authority/device status
and HDP visibility before reading the fence.

As `amdgpu_ring` does without `support_64bit_ptrs`, VCN pointers wrap by
the 1024-dword buffer mask. One gap distinguishes empty/full: at most three
256-dword client frames are pending. `Busy` changes no sequence or pointer;
after doorbell publication, submission always returns its sequence so a
later error cannot discard the resources needed by a published job. Frame,
ring-wrap/backpressure and publication-revocation models cover this API.
The opt-in `amdgpu.navi48_media` retains the VCPU after both proofs and
publishes logical ring 3 as `AMDGPU_HW_IP_VCN_ENC`, instance 0/ring 0.
VCN5 uses this unified ring for decode and encode; legacy VCN_DEC and JPEG
remain unavailable. A separate MMHUB VMID manager lends VMIDs 1..7 while
sharing the client's GMC12 root/PASID and generic CS resource retention.
Media jobs reject user-fence chunks before publication. Submission returns
synchronously after publication; CS then defers all BOs/mappings until the
translated fence or proven reset, with no intervening await. INFO_HW_IP
reports the VCN5 discovery version and Linux's 256-byte start/4-byte size
alignment, and derives usable rings from the proven registered submitter.
INFO_MAX_IBS reports eight for this ring. No codec profile or JPEG capability
is added by this transport interface; known-stream validation remains open.

Before exposing clients, `unsafe Vcn::prove_ibs().await` also runs the fixed
Linux `amdgpu_vcn_unified_ring_test_ib` encode/decode session create/destroy
messages. It requires the interrupt proof's drained ring with no intervening
client publication. `IbTesting` and a pending `ib_result` are stored before
the first await. A separate retained reservation owns the 128 KiB encode
context and six IB/message pages. Kernel VMID0 alone reads those fixed IBs;
the client VMID checks are unchanged. A new unified frame flushes HDP, emits
all four session IBs and a new fence/TRAP/END. Completion requires fence,
RPTR, exact fresh source-119 delivery and routed CPU MSI, plus immutable
command pages/padding and the existing entire fence-page guards. The wait
is bounded to one second; failure/cancellation retains all published storage
and refuses stop/retry, requiring device recovery.

Success is `IbVerified`; the boot client's fence-reader/publication gate
requires it. The same test runs after media recovery before reopening
retirement. `Vcn::ib_result` and platform `Diagnostics::media_ibs` preserve
the phase's proof or failure separately from the overall media cycle.
Proven VCPU/LMI shutdown also makes the auxiliary reservation reusable.
Proof sequences skip zero on wrap because startup clears the fence word;
normal client physical sequences continue wrapping through zero. Model
coverage includes both firmware engines, application submission after proof,
partial/failed/cancelled IBs, immutable command guards and wrapped proofs.
Native Rust tests exercise the production session-message and IB builders.
Static wire contracts are reviewed regression data, not independent external
conformance. Session messages exercise transport, not video-frame codecs.

The opt-in `amdgpu.decode_proof` additionally requests
`unsafe Vcn::prove_decode().await` after the session IB test. It uses IGT
GPU Tools 2.4's fixed AVC stream, create/decode/destroy messages and scaling
data (pinned hashes and MIT notices under `drivers/gpu/fixtures/vcn5`).
An independently reserved arena owns the 128 KiB session context, messages,
feedback, input, DPB/context, target and commands. Guards bracket the arena
and both sides of the output. Descriptor addresses are validated within
48 bits and match the unchanged IGT constructors for those owned addresses.
There is no intervening client job before this kernel-VMID0 proof.

`DecodeTesting` and pending `decode_result` precede allocation publication's
first await. Every page, including the target, is initialized; copying the
reference checksum into the target is never a production operation. One
new frame runs all three IBs and requires fresh fence/RPTR/trap/CPU evidence.
The 737280-byte output must sum to IGT's `0x20345d8`, with command pages,
padding, arena/output guards and the original fence guards unchanged.
`DecodeChecksum(actual)` distinguishes wrong/missing pixels from transport
failure. Bulk initialization/readback yields between pages, with no IRQ-safe
lock across awaits. Failed/cancelled work retains the full reservation and
refuses stop or replay; successful VCPU/LMI shutdown permits reuse.

`DecodeVerified`, `Vcn::decode_result` and platform `Diagnostics::media_decode`
preserve completion and output evidence. A requested decode proof is repeated
after media recovery before retirement reopens. Without native media clients
the flag runs the proof then completes the existing stop/power-down cycle;
with clients it retains the proven VCPU. This flag advertises no codec
profile. Models simulate device output only to test completion, checksum and
storage rules; actual AVC decoding remains an end-of-bring-up silicon test.

The same `amdgpu.decode_proof` sequence now also calls
`unsafe Vcn::prove_hevc().await` after AVC and before any requested encoder
proof. This separate retained Main8 arena uses an original 128×128 IDR
fixture, independently decoded with pinned FFmpeg 8.0. Its four luma regions
and distinct chroma values must match every byte of the 24576-byte NV12
output, so equal-checksum corruption is also refused (`DecodePixel(offset)`).
Mesa26.2.4 HEVC type layouts and IGT2.4 unified descriptors provide the
retained wire-data provenance; native Rust tests exercise the actual builders. SPS needs three DPB slots;
VCN5 64-byte DPB alignment, 128 KiB session and Main8 hardware context sizing
follow `ac_vcn_dec.c`. Six guard pages bracket context, DPB, output and arena;
input/scaling/IB bytes and firmware feedback error bits are checked as well.

`HevcTesting`, pending `hevc_result` and the published reservation precede
the first await. Fresh fence/RPTR/trap/CPU delivery is required independently
of AVC. Success records `HevcVerified`, `Vcn::hevc_result` and
`Diagnostics::media_hevc_decode`; failure/cancellation retains all storage,
closes client submission and requires whole-device recovery. A successful
owned VCPU/LMI stop permits reuse. Cold boot and recovery run both requested
picture proofs before reopening media clients; encode can follow either the
session, AVC or HEVC proof. The existing `media_decode` diagnostic continues
to hold AVC evidence separately. HEVC codec capability rows remain unadvertised:
Main10, profile/resolution ranges, inter pictures and application acceptance
are not established by this Main8 fixture or synthetic models. Regeneration,
source hashes and exact limits are documented in `fixtures/hevc/README.md`.

The decode sequence additionally runs `unsafe Vcn::prove_hevc10().await`
after Main8. It owns a distinct Main10 arena and records `Hevc10Testing`,
`Hevc10Verified`, `Vcn::hevc10_result` and `Diagnostics::media_hevc10_decode`.
The original 128×128 Main10 IDR has nonzero low two sample bits; independent
FFmpeg decoding matches every source sample. Every byte of the 49152-byte
MSB-aligned P010 output must match, including the low precision bits and zero
packing bits. NV12 conversion or 8-bit round trips cannot satisfy this proof.
Mesa's Main10 context formula yields 37888 bytes; three swizzled DPB slots
occupy 110592 bytes, distinct from the linear target. DT pitch is 128 samples
(256 bytes); UV begins after 32768 bytes. HEVC message depth-minus8 is two
for both planes, with `p010_mode` and `msb_mode` set. The same fresh completion,
full input/IB/feedback/guard checks, retained cancellation/failure and owned
stop/restart rules apply. Boot and recovery require all requested picture
proofs before clients reopen; encode uses the latest Main10 completion.
Host comparison and fixture regeneration accept `--main10` and preserve the
Main8 checks. HEVC rows remain unadvertised; two fixed intra pictures do not
establish inter prediction, full profile/range or application acceptance.

The requested decode chain next runs `unsafe Vcn::prove_vp9().await` with an
original 128×128 Profile0 error-resilient keyframe. The retained tier3
unified-DT arena uses the decoded linear NV12 target directly and emits the
actual empty reference-list package; it allocates no worst-case 8K legacy
DPB. Mesa's five probability contexts, segmentation, motion-vector and
probability-table formula still requires 10857728 bytes of context, and the
complete page-aligned arena is 11071488 bytes. Session default probabilities
come from the pinned Mesa table; the per-frame probability page is separately
writable by firmware. All 24576 decoded bytes, guards, bitstream, initialized
probability defaults, IBs/padding and feedback must pass, with a fresh
fence/RPTR/IH/CPU completion. `Vp9Testing` and the published arena precede the
first await; cancellation/failure retains the arena and closes clients until
owned recovery. Success records `Vp9Verified`, `Vcn::vp9_result` and
`Diagnostics::media_vp9_decode`; owned stop permits reuse. Cold boot and
recovery run VP9 after Main10 before any requested encoder or client work.
Allocation refusal occurs before changing state/result/sequence or publishing
VP9 addresses. Codec rows remain gated: this fixture establishes neither
Profile2, inter-frame references, full profile/range nor application behavior.

The current transport/IB, AVC/Main8/Main10/VP9 decode, AVC encode and JPEG
transport/decode retained arenas total 30035968 bytes. Firmware/TMR and
current display reservations are additional variable costs; admission uses
actual contiguous `Pool` availability, including fragmentation, rather than
assuming that a 256 MiB visible BAR guarantees success. The subsequent client
VRAM carve retains its existing 64 MiB minimum and driver reserve policy.
Synthetic VP9 models omit the opaque context tail but count every zeroing
write before publication, keeping test storage below 256 KiB per model.
Exact fixture/source provenance and limits are in `fixtures/vp9/README.md`.

The same requested decode chain next runs `unsafe Vcn::prove_vp9_10().await`
on an original 10-bit Profile2 keyframe. `Vp9TenTesting/Verified`,
`Vcn::vp9_10_result` and `Diagnostics::media_vp9_10_decode` retain separate
proof/state/arena ownership. Every byte of the 49152-byte P010 output must match, including nonzero
low 2 sample bits and zero packing bits; an 8-bit intermediate is refused.
Mesa's actual 10-bit context formula adds 65536 bytes, totaling 10923264 bytes;
the complete retained arena is 11161600 bytes. Tier3 references, full guard,
input/IB/feedback checks and fresh completion rules match Profile0. Cold boot
and recovery run Profile2 after Profile0 before requested encoders/clients.
A synthetic context model stays below 256 KiB while counting initialization.
Retained VCN proof arenas now total 41123840 bytes; adding JPEG transport/decode
yields 41197568 bytes before variable firmware/display claims and later codecs.
The original-picture generator supports `--profile2`. Native Rust tests
exercise the retained P010 descriptor/ownership paths. Codec capability rows
remain gated pending inter references, range and actual client acceptance.

The requested decode chain next runs `unsafe Vcn::prove_av1().await` on an
original 256×128 lossless Main8 reduced-still keyframe. It owns separate
`av1_memory`, `Av1Testing/Verified`, `Vcn::av1_result` and platform
`Diagnostics::media_av1_decode`. Exact NV12 pixels, input/IB padding/guards,
immutable initialized decoder CDF, successful feedback and fresh native
fence/RPTR/IH/CPU delivery are required. Mesa tier3 binds the current linear
surface and an empty dynamic reference list, with no monolithic DPB. Actual
VCN5 AV1 version2 sizing requires a 36688896-byte hardware context and four
20480-byte initialized default CDFs. The complete arena is 37076992 bytes;
128 KiB stream and 24 KiB per-frame segment/film-grain storage remain reserved.
Firmware/TMR/display are additional costs. VCN proofs now total 78200832 bytes,
or 78274560 bytes with JPEG, before separate new encoder roundtrip arenas.

The private shared `decode_av1_frame` accepts a copied map/base whose caller
retains a published Reservation, compact stream bytes, validated parsed
fixed-sequence `Keyframe`, explicit pixel tolerance and Observer. It validates
lengths/tile coverage/quant/filter/tx bounds before arena writes or address
publication, checks every expected quadrant pixel and returns completion,
absolute pixel-error sum and observed maximum. It owns no arena retirement;
caller preserves storage on every await/failure and only an owned stop/reset
permits reuse. Static proof uses zero tolerance. Dynamic encoder roundtrip
uses separately retained storage and parses actual firmware output first;
no pixel or codec claim follows solely from software model execution.

Boot/recovery run AV1 after Profile2 before requested encoders/clients. Failures
and cancellation retain published memory and close admission. Sparse models
store defaults and meaningful pages below 512 KiB while counting every omitted
context initialization write; full hardware reservations are unchanged.
Reviewed surface geometry, Mesa-derived CDF/message/IB data, original
picture assets and their hashes are retained for native Rust regression tests.
The separate picture generator invokes supplied libaom/FFmpeg tools. Provenance is in `fixtures/av1/README.md`.
A separate requested AV1 Main-profile 10-bit precision proof next runs
`unsafe Vcn::prove_av1_10().await`. It owns `av1_10_memory/result`,
`Av1TenTesting/Verified`, `Vcn::av1_10_result` and platform
`Diagnostics::media_av1_10_decode`. Its original independent lossless 256×128
picture has nonzero low sample bits; every one of the 98,304 P010 bytes,
including six zero padding bits per sample, must match. Actual Mesa messages
select bit depths minus8=2 and P010/MSB mode, with no 10-to-8 dithering. Actual
Addrlib derives sample pitches 256/128 and UV offset 65,536 on both revisions.
Context and initialized decoder CDF are depth-independent and unchanged;
the separately retained arena is 37,126,144 bytes, not just the 49,152-byte
increase in target size. Native guards, immutable input/CDF/IB checks, feedback,
fresh fence/modular RPTR/IH/CPU completion, failure/cancellation quarantine
and owned-stop retirement use the same contracts as Main8. No static or
encoder roundtrip arena is shared or released by ordinary completion.

Cold boot/recovery run Main8 then Main10 before the encoder/client chain.
Both native submit state gates and requested proof-result readiness accept
only completed appropriate stages; encoders consume the newest completion.
The Main8/parsed-Keyframe/dynamic320 APIs remain unchanged. The full retained
VCN chain including this proof and AVC encoder is 115,326,976 bytes before
separate HEVC/AV1 encoder roundtrip and variable firmware/display claims.
Every additional owner uses actual checked pool admission, including pressure
and contiguous-hole refusal, with no presumption of a larger visible BAR.
Pinned primary/fixture references and precision provenance are in
`fixtures/av1/README-10.md` and `research/summaries/rx9000-av1-p010.md`.
Inter references, film grain, ranges and actual clients remain unproven;
codec capability rows and DRM/ACCEL gates remain closed.

The opt-in `amdgpu.encode_proof` requests `unsafe Vcn::prove_encode().await`
after the session IB proof (and after decode when both flags are requested).
It runs IGT 2.4's fixed 160x128 NV12 input through create/IDR/close tasks on
kernel VMID0. Packet builders match the unchanged VCN5 IGT constructors;
the input frame has a separate hash manifest and 2014/2023 AMD MIT notices
under `drivers/gpu/fixtures/vcn5/encode`. A separate retained arena owns
session/CPB, pitched immutable input, metadata, feedback, output and commands.
The output has the entire declared `0x1f000` range backed, with guards on
both sides; the source test's smaller allocation is not copied.
Its three AVC session headers use the interface selected from the retained
authenticated firmware, exactly as the newer HEVC/AV1 proofs: major1 with
minor>=8, clamped to1.10. Missing/unsupported interface refuses before fresh
arena allocation, state transition or address publication, preserving any
preclaimed unpublished storage and the prior proof. Cancellation/failure
retention and owned retirement are unchanged. Native Rust tests exercise the
reviewed IGT1.9 wire values and1.8/1.9/1.10 session selection. External source
conformance, physical completion and capability gates remain separate.
The version is retained common-header metadata corresponding to the loaded
payload, with the same header-authentication limit as `FW_VCN` above.


`EncodeTesting` and pending `encode_result` precede the first await and
publication. Each arena page is initialized, including fresh zero feedback
and output. Native fence/RPTR/source119/CPU evidence precedes reading feedback.
Word 1 must be valid, word 8 must match the owned start offset 0, and word 6
must be a nonzero end within the declared output range; only end minus start
is accepted. A bounded
Annex-B inspector requires matching SPS/PPS references, 160x128 eight-bit
4:2:0 dimensions and IDR/I-slice headers. This is header evidence, not a
complete H.264 validator or picture-quality proof. Command pages/padding,
input/pitch padding, arena/output guards and the original fence guards must
remain intact. Bulk work yields by page without an IRQ-safe lock.

`EncodeVerified`, `Vcn::encode_result` and `Diagnostics::media_encode` retain
the completion, encoded byte count and profile. Failure/cancellation retains
all backing and closes client publication; successful VCPU/LMI shutdown
permits reuse. The requested proof repeats after media recovery before any
ledger reopens. Without media clients, the flag finishes the existing
stop/power-down cycle; with clients, the proven VCPU remains retained. No
codec profile is advertised by this proof. Synthetic header output in the
model verifies ownership, parsing and completion contracts; actual encoding
and picture-quality acceptance remain physical tests at the end of bring-up.

Before spawning the deferred media worker or carving the visible client heap,
`ColdBoot::prepare_media_transport` admits the complete requested footprint.
`Vcn::reserve_proofs` and JPEG's counterpart use exact per-codec arena constants,
including both roundtrip arenas, Main10 profiles and JPEG client slots. VCN and
JPEG owners stay local until both full sets fit. No power message, dispatch
registration or media address is published on refusal; only new unpublished
reservations drop, and pressure can be released before retry. Existing retained
pins are never replaced/released by this transaction. Unsupported encoder
firmware refuses the whole request without silently trimming its profile set.
The prepared request is immutable; startup and new resume owners check the same
request before power. Failure/cancellation after publication keeps the existing
retained-engine/reset contract. The checked startup claim precedes client carve,
so the asynchronously scheduled worker cannot discover that clients took its
proof memory first.

The full VCN chain currently claims155734016bytes after the384x128 HEVC
correction: all requested decoders through AV1 Main10, AVC encode and both
HEVC/AV1 encoder roundtrips. JPEG proof plus decode adds73728bytes; keeping
its four64KiB staged client slots adds262144. These are distinct retained
arenas, not reusable scratch. Firmware, existing display/queue allocations and
inventory exclusions have already reduced actual `Pool::available()`. Client
carve then preserves max(32MiB, aperture/8 capped512MiB) for later driver owners,
uses actual checked contiguous2MiB-aligned reservation and requires at least
64MiB. Small-aperture admission never halves the post-proof remainder. Missing
space refuses a client VRAM heap or the complete media request, as applicable;
there is no universal all-features-fit promise for256MiB. Later display requests
must still obtain their exact checked backing. Draw proof arenas use System/GTT
and do not consume this BootPool reserve. Native regressions use a real256MiB
Pool, variable firmware/display claims, pressure/refusal/retry, old startup-order
reproduction, published-pin retention and full proof-to-real-client submission
through stop/restart. Capability/profile/range rows remain separately gated.
Clean S3/BACO resume drops and reclaims the old stopped proof owner before
this admission. Fault recovery instead keeps the old whole owner quarantined;
its complete media backing and the carried client heap remain charged. A
256MiB aperture can therefore refuse the new full request and remain lost
after a fault, even when the initial request fit. No uncertain old owner is
reclaimed to force recovery admission.

The same `amdgpu.encode_proof` sequence additionally requests
`unsafe Vcn::prove_hevc_encode().await` after AVC encoding (and all requested
picture decoders), including after coordinated media restart. The VCN owner
receives the authenticated firmware version in `Vcn::new`; Mesa's version
bitfields select interface1.min(minor,10), with a minimum1.8 for the dependent
slice-address template. Unknown majors/older interfaces refuse before
allocation/publication. No client job can intervene between proof sessions.

`HevcEncodeTesting`, pending `hevc_encode_result` and publication of both
reservations precede the first await. The552960-byte encoder arena backs two
98304-byte reconstruction slots (196608bytes collectively), separate per-slot metadata,
128KiB session, immutable pitched input, output and guarded commands. Mesa's
VCN5 source definitions provide the reviewed wire/sizing provenance. VPS,
SPS and PPS are retained static fixture data originating from Mesa's bitstream
writers; the80-byte aligned prefix is preserved. Native Rust tests exercise
production builders without compiling those external sources. Feedback word1 must be valid, word8 must equal80,
and end word6 must exceed start within the entire backed0x1f000 output range.
Fresh ring/fence/source119/CPU evidence is required before reading any output.
The fixed parameter sets/padding and single PPS0 IDR I-slice gate must match.

Before recording success, the exact encoded output is copied into a separately
retained462848-byte Main8 decode arena. Its dynamic bounded byte count, two-slot
DPB/context, compact NV12 target, flat scaling and fixed producer SPS/PPS params
match unchanged Mesa's generic decoder and HEVC builders. A second fresh physical
sequence/IRQ completion must precede every output component comparison. Each
component's absolute error must be<=4 and the mean error<=1; output starts zero,
so stale/empty pictures cannot satisfy the source. Both sessions' input/command/
guard checks and decoder feedback must succeed. `EncodeRoundtripProof` contains
separate encoded/decoded completions and fidelity metrics; only its decoded
completion is the newest fence. `HevcEncodeVerified`, `Vcn::hevc_encode_result`
and `Diagnostics::media_hevc_encode` preserve this evidence. The client fence
reader requires this roundtrip when encoding was requested, through boot and
recovery. Every failure/cancellation retains both arenas and closes publication;
only owned VCPU/LMI stop or whole-device retirement permits reuse. A refused
unpublished allocation leaves the previous transport proof usable.

The fixture's original input, unchanged Mesa-generated headers and independent
x265 IDR are decoded by FFmpeg8.0 to every source sample in host tests; this is
a reference validation, not evidence of physical firmware quality. Native models
simulate encoder/decoder writes solely to check ownership/error/completion rules.
HEVC capability/profile/range rows remain unadvertised by a single intra proof;
inter prediction and application acceptance still require their own evidence.

The same requested encode chain then calls `unsafe Vcn::prove_av1_encode()`.
It emits one320x128 Main8 reduced-still keyframe, one5x2-SB64 tile and no
inter references. CQP1 respects Mesa VCN5's AV1 minimum; the actual firmware
quant/filter/transform fields are parsed rather than inferred lossless. The
fixed CPU9-byte sequence header comes from unchanged Mesa's bitstream writer.
This width respects Mesa VCN5's320-pixel minimum. Its physical16-byte prefix has7zero alignment bytes that must remain intact;
those bytes are excluded from the compact logical stream sent to the decoder.
Feedback word1 must be valid, word8 must equal16 and word6 must be a greater
end within the fully backed126976-byte output. The bounded OBU parser accepts
exactly one frame, checked eight-byte LEB128 length, fixed producer shape,
signed quant deltas, loop-filter levels/delta updates and transform mode. It
rejects unsupported tools, extra OBUs, truncated lengths and nonzero alignment.

`Av1EncodeTesting`, pending result and both published reservations precede the
first await. The encoder arena is1884160bytes, including Mesa-sized947200-byte
search database, two196608-byte reconstructions,25088-byte per-frame metadata,
81920-byte encoder CDF, input/output and guarded commands. The encoder CDF is
firmware READWRITE; boundary checks retain it without assuming immutability.
Actual unchanged Mesa constructors, setup sizing and native CDF array export
verify these constants; actual GFX12 Addrlib checks encoder pitches512/256 and UV65536
on both supported revisions. Default encoder and decoder CDF tables differ.

The separate37101568-byte AV1 roundtrip arena retains the compact exact output
through `decode_av1_frame`, using parsed tile offsets/size, quantization and
filter/transform fields. The actual decoder target uses Addrlib sample pitches384/192, UV49152 and
73728-byte backing for61440meaningful components. The helper's actual
full36688896-byte context and
separate decoder CDF are backed in full. Only a second fresh native fence,
RPTR/source119/CPU completion, every component's error<=4, mean absolute error<=1
and all stream/CDF/command/feedback/guard checks permit `Av1EncodeVerified` and
`Vcn::av1_encode_result`/`Diagnostics::media_av1_encode`. The published result
records separate encoded and decoded completions; the decoded completion is
newest. Boot, recovery and requested client fence admission require the whole
chain. Cancellation or uncertain failure retains both arenas until proven
VCPU/LMI stop or whole-device retirement; unpublished allocation failure
preserves prior transport and allows retry. These two arenas add38985728bytes
to the complete retained proof budget, independently of the static decoder.

Original libaom3.13.1 fixtures, actual Mesa CPU sequence and FFmpeg8/libaom
roundtrip validate every source sample independently. Host parser regressions
cover real lossless/lossy syntax and malformed/dynamic fields; native DMA
models cover ownership/completion/error paths without implementing a codec.
No AV1 codec/profile/range is advertised by this one keyframe. Inter prediction,
other profiles/ranges, physical execution and application acceptance remain
separate acceptance requirements.

The opt-in `amdgpu.jpeg_proof` adds a retained JPEG5.0.0 static-power
transport cycle while VCN holds the shared NBIO media doorbell range. Public
`amdgpu_jpeg_navi48::{Jpeg,State,Proof,Error}` provides unsafe `new`, `start`,
`prove` and `stop` with state/result snapshots. JPEG accepts exactly one
VCN5 discovery instance, the matching NBIF6.3.1/GC12.0.0/12.0.1/MMHUB4.1 layout and a validated
GMC/VRAM pool. Its owned doorbell is `0x311`. It never programs or disables
NBIO's shared range, and VCN refuses start/teardown under an enabled JPEG
doorbell. The coordinator excludes shared-register and PM writers.

`unsafe Smu::set_jpeg_power(bool).await` issues SMU14 instance-0
PowerUpJpeg/PowerDownJpeg after fresh protection/static-media checks, using
the same retained runtime/cancellation rules as VCN. JPEG's ONO1 fields and
clock gates are independent; register updates preserve VCN's ONO2..5 fields.
The dispatch registration exists before startup, so every published JPEG
owner participates in reset accounting. The allocation is published before
startup's first await and retained on any
failure or cancellation. Its two guard pages bracket the ring, fence/shadow
page and immutable IB page. Both GPCOM fence data dwords are reserved before
the separate CPU write-pointer shadow; neither aliases the other.

`prove` requires a registered `Key::Jpeg { instance: 0 }` kernel-VMID0/PASID0
owner and the independent IH service. A new direct pitch write/RPTR witness
precedes a kernel IB with a different pitch value. MMHUB4.1 start/end and
HDP ordering, IB/fence/trap words match unchanged local Linux constructors.
Fresh fence/RPTR, exact client/source153 and routed CPU evidence are required,
with intact ring/IB words, padding and guards. `jpeg0_traps` records the exact
kernel context; dispatch separates JPEG from VCN source119 and attributes
unidentified MMHUB faults to both engines' matching VMIDs. Interrupts wake
owners but never complete a fence from payload data.

Retirement requires the ring/job drain, all JMI/core read/write-clean bits
and no pending MC writes, both before and after JMI reset. Only then may the
JPEG doorbell/clocks/ONO1 shut down and the allocation become reusable.
The boot cycle stores pending `Diagnostics::media_jpeg` before awaiting,
retains `jpeg_state`, and retires its extra interrupt owner only after proven
shutdown and SMU power-down. A requested cycle repeats after recovery before
any client ledger reopens. A live unretired JPEG owner makes a four-owner
recovery receipt incomplete, requiring whole-device recovery instead.

`amdgpu.jpeg_proof` proves JRBC/IB/interrupt/retirement transport without a
picture. It advertises no JPEG client ring or codec capability by itself.

`amdgpu.navi48_media` also runs that JPEG cycle (plus a requested picture
proof) and keeps the drained ring registered and powered for clients:
`unsafe Jpeg::open_clients()` moves `Verified`/`DecodeVerified` to `Clients`
and publishes a separate kernel arena of `SLOTS` (4) x `SLOT_BYTES` (64 KiB)
IB-copy slots. As Linux's parse_cs path (`amdgpu_cs_patch_ibs`,
`amdgpu_jpeg_dec_parse_cs`), each client IB is read through the client's
mapping, checked by `validate_ib` and copied by `unsafe Jpeg::stage(slot,
copies)` to 256-byte-aligned VMID0 addresses inside one slot. `validate_ib`
is stricter than Linux: TYPE0/TYPE3 writes to GPCOM (0x404d-0x404f), the
JRBC ring/IB controls (0x4080-0x408d, 0x4094), the LMI JRBC/decoder VMID and
fence-address block (0x40a0-0x40af) and the IB BAR/size (0x40b6-0x40bf) are
refused, because a VMID0 copy could otherwise escape the client's address
space; Mesa's JPEG paths use none of them. `unsafe Jpeg::submit(job)` accepts
only staged slot addresses and emits jpeg_v4_0_3's frame in
`amdgpu_ib_schedule` order: MMHUB4.1 flush on invalidation engine 1 (Linux's
ring-order allocation after VCN0's engine 0) with semaphore and PTB wait,
IH_VMID_0_LUT_MM, insert_start, HDP flush, each IB at JRBC VMID0 with
decoder VMID `v | v << 4 | v << 8`, GPCOM fence/trap, insert_end. Register
packets use NORMALIZE_JPEG_REG_OFFSET (no RRMT). The 1024-dword ring wraps by
its buffer mask with one-gap full detection; `Busy` changes no sequence or
pointer. Client sequences wrap through zero. `Jpeg::fence_reader()` exists
only in `Clients` and checks live authority/device status/HDP visibility.

`unsafe Jpeg::reset_stop().await` retires a possibly hung ring
(jpeg_v5_0_0_stop): JMI soft reset, fresh clean-DMA bits, ring hold, doorbell
and power gating; only success marks every arena stopped. The platform
publishes logical ring 4 as `AMDGPU_HW_IP_VCN_JPEG` instance 0/ring 0 on the
shared MMHUB VMID manager; user fences are refused; up to eight IBs fit one
256-dword frame. A slot records its job's ticket and is reused only after that
ticket completes; replay after a reset reuses the retained copy. A JPEG
timeout resets JPEG alone (retire, PowerDownJpeg/Up, start, transport and
requested picture proofs, reopen, replay innocent jobs). A VCN timeout or
coordinated fault recovery retires JPEG first, since VCN's stop closes the
shared range, and re-proves it after VCN; the recovery receipt then includes
the JPEG registration as its fifth owner. INFO_HW_IP reports JPEG under the
VCN discovery entry with Linux's 256/64 alignment. Codec/profile capability
and physical acceptance remain open.

`amdgpu.jpeg_decode_proof` implies that transport cycle and additionally calls
`unsafe Jpeg::prove_decode().await` on a newly drained kernel VMID0 queue.
`DecodeTesting` and pending `decode_result` precede the first await and arena
publication. A separate reservation retains IGT 2.4's fixed JPEG input, guarded
24 KiB pitched NV12 target and immutable IB page. The 406-byte input, source
archive/hash and 2017/2023 AMD MIT notices live in `fixtures/jpeg5`; the IB
matches unchanged IGT JPEG5 register-selection and construction functions.
All pages start at known values, with guards around the arena/input/target.

Fresh fence/RPTR/source153/CPU evidence is required before summing the active
64x64 luma and 64x32 interleaved chroma bytes at pitch 256. Their combined sum
must equal 262144; untouched zero output cannot satisfy it. `DecodeChecksum`
retains the observed sum on mismatch. Input and zero padding, picture/transport
IBs, historical ring commands, kernel fence/shadow page and all guards must
remain intact. Bulk initialization/readback yields by page. Only a current,
drained transport witness may enter this proof; it clears both idle GPCOM
fence dwords and uses a new nonzero sequence, rejecting stale fence contents.

`DecodeProof { completion, output_sum }`, `DecodeVerified`, `decode_result`
and platform `Diagnostics::media_jpeg_decode` retain picture evidence separately
from the original transport result. The overall JPEG cycle returns its latest
proof and performs normal DMA-clean shutdown/power-down before retirement.
Failure/cancellation retains both allocations and closes clients; only proven
JRBC/JMI shutdown makes either allocation reusable. A requested picture proof
repeats after media recovery before any ledger reopens. This opt-in advertises
no codec capability. Synthetic model pixels exercise lifetime/checksum rules;
physical picture execution and codec conformance remain acceptance work.

The opt-in `amdgpu.media_proof` boot argument requests a retained native
power-up/start/fence/interrupt/stop/power-down cycle after the GC12/SDMA interrupt
proofs, before publishing clears or allowing any client slot. Its pending
state is stored before the first await; error/cancellation gates all
client submit wrappers and returned failure quarantines the IH service.
`amdgpu_navi48_platform::Diagnostics::media_transport` exposes the result.
`media_state` preserves the VCPU phase after cancellation or failure.
The media interrupt handle is retained before source enabling and retired
only after proven VCPU/LMI stop and power-down. A retained media owner must
join the fourth retirement before global re-arm; it cannot be omitted from
a three-queue receipt.
Explicit whole-device recovery repeats the requested proof with fresh
owners. `media_proof` alone adds no client ring; `navi48_media` retains and
exposes the proven unified transport described above. Codec execution,
JPEG and physical MSI/engine acceptance remain open.

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
`amdgpu_vram::UnmappedPool::from_owned(gpu_address, len, protected)` is the
same allocator for VRAM no CPU mapping reaches: `reserve_aligned` hands out
`UnmappedReservation`s (GPU address and size only), returned on drop, so
their holder keeps them until the GPU can no longer reach them and has the
GPU clear them before a client sees them.
`Pool::claim(range)` / `UnmappedPool::claim(range)` pin a fixed,
pool-relative range permanently, as `amdgpu_bo_create_kernel_at` pins a
firmware range: it may cover protected ranges (merged with them) but is
`Busy` over any live or retired reservation and `Invalid` past the pool.

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
`unsafe Plan::unmapped_pool()` (called first) returns the VRAM above the
visible mapping, less every protected range there, as an `UnmappedPool`, or
`None` when the BAR shows all of VRAM; the same ownership contract applies.
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
14-bit pitch and viewport fields are checked before writes. Initial activation
normalizes rotation, mirroring, separate alpha, metadata alignment, trusted
metadata, VMID and stereo/flip controls before arming the address; it does not
depend on a firmware owner's reset values. Unrelated fields are preserved. The
chroma request sizes are cleared rather than left behind, so a previous owner's
chroma plane cannot keep fetching. `blank` waits up to 100 ms for the pipe's
outstanding requests to retire; a power-gated pipe reads back zero and needs no
wait. As `hubp2_set_blank_regs`' REG_WAIT, a pipe that never retires is logged,
counted (`blank_stalls()`) and blanked anyway.

`amdgpu_dcn_plane` programs the rest of the plane path. The DPP and OPP banks are
DCN base index 2 while the MPC bank is index 3. `Dpp::program` enables the pipe
clock, sets the converter format and bypasses the scaler outright rather than
programming unity taps, with the recout and combiner size matching the active
area. It initializes CNVC zero expansion and RGB routing, disables inherited
separate-alpha processing and ROM degamma, and bypasses the color-management
block. Scaling-444 bypass still initializes autocal/boundary mode and the
opaque RGB line buffer (all three banks, 63 maximum partitions). These fields
and constructor bounds are shared by the verified DCN30/DCN314 layouts.
`Mpc::mux_plane` bypasses any inherited output-gamma LUT, binds one combiner to
one DPP and one OPP and points that
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

`display_paths(gpu, vbios)` walks `display_object_info_table_v1_4/v1_5`, resolving
DCN314, Navi22/DCN3.0 or Navi48/DCN4.0.1 from discovery. It decodes each path's
connector and UNIPHY transmitter separately from its hardware AUX and HPD lines.
Object ids are `ObjectID.h` values, as Linux's `bios_parser_common.c` decodes
them: connectors HDMI-A `0x0c`, DisplayPort `0x13`, eDP `0x14`; encoders UNIPHY
`0x1e`, UNIPHY1 `0x20`, UNIPHY2 `0x21` (two transmitters each, by enum id) and
UNIPHY3 `0x25` (transmitter G only). `displayobject.h` numbering is not used.
Connector record offsets are relative to the display-object table. The I2C and
HPD record IDs are keys into `atom_gpio_pin_lut_v2_1`; the GPIO register and bit
are matched against the discovered DCN bank to obtain the AUX channel and
one-based ATOM HPD selector. A DDC pair may be identified by its CLOCK bit 0
or DATA bit 8; both resolve to the same channel, as in Linux's DCN GPIO
translation. Other bits and registers outside the supported DDC pairs are
refused. `Path::aux` is `None` when absent; `hpd` is zero
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
bounds admit all six Navi22 or four Navi48 transmitters and frontends. Both
discrete profiles reject DPIA routes; Phoenix retains its five DIG candidates.

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
  The canonical minors are real children of that function's `drm/`
  directory, so udev's parent walk reaches PCI for Xorg GPU selection.
  Class/devnum symlinks name those canonical minors; the former
  `/sys/devices/platform/narf-drm/*` paths remain compatibility aliases.
- Once that sysfs projection is complete, the PCI parent, primary node, and
  render node emit ordered ADD uevents inside the bounded boot replay window.
  This is the interface by which udev applies the `master-of-seat` tag and
  logind reports the default seat as graphical to display managers.

## 4. Invariants & safety properties

- **GEM address leases:** logical object references alone never authorize
  retention of raw backing addresses. CPU mappings, GPU PTEs (including
  removed entries awaiting jobs), and deferred CPU user-fence writes retain
  the exact backing lease until their last access. A coordinated GPU move
  excludes new jobs/VA edits, waits all affected VM jobs, copies into private
  backing, rewrites the existing PTEs and replaces their backing leases before
  releasing admission. CPU leases cannot be revoked by this path. A copy
  requires exclusive backing ownership and no unsignalled reservation fence
  when committing. Asynchronous invisible-VRAM copying retains old GPU leases
  and keeps the destination private until then. Before starting it, an address
  lease census permits only registered idle GPU mappings and the coordinator:
  a deferred CPU writer or unregistered lease refuses the copy before staging
  can read its source. Kernel DMA owns both source
  and destination until actual completion, independently of waiter lifetime;
  cancelled move fences block subsequent user jobs, including jobs that omit
  the object from their BO list. Scratch reuse and recovery replay cannot
  overwrite a predecessor's still-live transfer.
  Same-card PRIME sharing preserves identity, metadata and reservation across
  relocation.

- GPU DMA targets are validated against its IOMMU context.
- A hung GPU causes no kernel hang — the driver domain takes the hit.
- GEM identity, shared metadata and reservations survive migration. Address
  leases remain stable until released. Moving a GPU-mapped BO additionally
  requires card admission exclusion and a complete PTE rebind before new
  jobs; CPU-mapped backing remains pinned. The source allocation survives
  until the complete destination copy succeeds.
- VM programming completion never substitutes for a job's lifetime fence.
  Reset generations invalidate retained submitters before queues are reused.
- Live userspace register queries validate the complete allow-listed range
  before accessing MMIO, under current PCI authority, the retained hardware
  owner and a GC power reference.

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
