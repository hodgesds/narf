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

### Navi 48 PCIe probe (RX 9070 XT)

The next discrete target is Navi48, selected from the September 2026
[Steam PC video-card survey](https://store.steampowered.com/hwsurvey/videocard/):
RX 9070 XT is the leading named AMD card at 1.42%. The larger generic
"AMD Radeon Graphics" entry does not identify a chip. This selection is a
dated snapshot, not a permanent popularity claim.

`1002:7550` binds as `Family::Navi4`, `asic="navi48"`. This ID also covers
RX 9070/GRE; neither SKU nor enabled CU count is inferred from it. Probe uses
the existing bounded PCIe discovery reader and total/visible VRAM accounting.
`DEV_INFO` requires exactly one GC0 12.0.1 discovery record and a GC topology
table, then reports `AMDGPU_FAMILY_GC_12_0_0` (152), eight hardware contexts,
and GMC12's 48-bit VA geometry. Shader geometry describes discovered maxima;
the active CU count, CU bitmap and enabled render-backend mask remain zero
until the cold-boot owner samples harvesting. `ACCEL_WORKING` remains zero.

`unsafe amdgpu_gfx12_topology::read` requires exclusive GRBM selector ownership
and ready firmware/power. It validates GC12.0.1 banks and discovery dimensions,
combines fused and inherited software SA/WGP/RB disable masks, and restores
the previous GRBM selector on success and failure within one capability
invocation. It never changes harvesting masks. `Topology` reports active CUs,
shader arrays, enabled RBs and Linux's 4×4 CU bitmap packing (SE4–7 in columns
2/3). Cold boot publishes this inventory to `DEV_INFO` after initial power
setup; it does not advertise queues or acceleration.

When VFCT has no image, VBIOS acquisition supports the SMUIO14.0.2 ROM read
ports (`0xe4/0xe5`, base index zero) only with matching GC12.0.1 and NBIO7.7.0
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
Navi48 with exactly one GC0 12.0.1 and MP0 14.0.2 or 14.0.3. Discovery selects
`amdgpu/psp_14_0_2_sos.bin` or `amdgpu/psp_14_0_3_sos.bin`; no revision fallback
or professional-SKU kicker firmware is used. `Firmware` and `Bootloader`
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
GPCOM ring after SOS and VRAM training. It requires GC12.0.1, MP0 14.0.2/3,
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
set through live registry/blob invocations. MP1 14.0.2/3 and SDMA7.0.0/1 select
revision-specific names. GC12.0.1, one VCN5.0.0 and DCN4.0.1 (including raw
4.1.0 discovery encoding) are required. Separate and unified MES images are
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
board-supported mask for GFX DPM and autonomous thermal/fan/electrical
protection, enables it and verifies the running mask and GFX frequency range.
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
transition, after checking every display consumer.

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
rates in kHz. Every consumer must remain retired. It reports the display count,
pins DCFCLK and UCLK to the reported maxima, disables UCLK switching, and sets
the requested display clocks, rounding mailbox requests up to MHz. Each floor
requires both mailbox acceptance and the corresponding bit from
`ReturnHardMinStatus`; its one-second deadline includes nested mailbox waits.
DISP/DPP/DTB replies are actual kHz, checked against the requested floor and
firmware ceiling. `Applied` distinguishes those actual rates from acknowledged
DCF/UCLK floor requests. FCLK follows DCFCLK on this ASIC; the unsupported
FCLK-switch message is not sent. This is a conservative pre-modeset policy,
not active-stream clock scaling or a bandwidth/watermark solution.

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
snapshot. No stream may use a stale snapshot after global clocks change.
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
progressive RGB timing with fixed refresh and one OPP per OTG. Interlace, DSC,
ODM combining and VRR are not represented by this request. `GlobalSync` supplies
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
Clocks remain on. This proves timing retirement only; it cannot authorize memory
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

Retirement parks output muxes first, then every MPCC top/bottom/OPP/update-lock
selector, and disables cursors on powered HUBPs. A shared 100 ms deadline bounds
all drain waits. Each MPCC must acknowledge IDLE or DISABLED with BUSY clear;
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
and packed `SurfaceFormat::{Xrgb8888,Xbgr8888}`. Rows are padded to 256 bytes;
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
sets uncompressed RGB8888, pixel pitch minus one, red/blue crossbar, primary and
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
Replacement and release are refused until an explicit retirement protocol
exists. Published backing remains excluded even if the owner is dropped;
unpublished backing is releasable because no address reached hardware.

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
firmware/FAMS and concurrent hub/VM/display/clock/reset/power writers. Native
header checks live in `tests/dcn401_vm.c`; physical card validation remains open.

`unsafe Otg::prepare_dpp(&mut ClockManager, &mut Dccg, &mut Gmc, pipe).await`
stages native DCN401 processing for the retained full-frame XRGB/XBGR8888
surface. ColdBoot/platform `prepare_display_dpp(pipe)` wrappers borrow the
matching retained owners after the kernel engine proofs. It requires the same
surface and DCN VM setup, current readback-checked clocks, matching stopped
timing and prepared RGB black OPP, and a disconnected, blank, drained HUBP.
Source and timing active dimensions must match; no scaling, crop, alpha blend
or multi-pipe composition is accepted. The selected DPP clock must be disabled,
resets clear, its cursor disabled with no pending update, and inherited CNVC,
scaler and CM updates complete. Test clocks and forced/manual line-buffer
power policy are rejected before writes. Other DPP instances stay untouched.

Preparation temporarily enables the native DPP clock (bit 4, no obsolete rate
divider), wakes scaler LUT and iSHARP memories with bounded asynchronous waits,
and rechecks stopped consumers after each wait. Native RGB8888 conversion uses
zero expansion and an identity CNVC crossbar; red/blue selection remains in the
HUBP. FCNV bias/scale and HDR multiplication are identity, pre-degamma/post-CSC/
gamma/keying/de-alpha are bypassed, and the encoded RGB values pass through.
The unused source alpha is not used by the line buffer; MPC preparation below
selects opaque blending. Scaler autocal is disabled, recout begins at zero,
and recout/MPC dimensions match the surface. Native `SCALING_444_BYPASS` (mode 0)
still configures a floating-point line buffer; mode 6 full bypass is not used.
Line-buffer configurations 1, 2, then 0 are selected using native capacities
970, 1290, 3430 and `ceil(width/6)` entries per row, requiring two rows for unity
scaling. Widths above 10290 reject as unsupported on this single-pipe path.
Adaptive filtering and iSHARP are disabled without programming coefficient RAM.

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
concurrent display/hub/VM/clock/reset/power writers. `tests/dcn401_dpp.c` checks
the native header contract. MPC and requestor preparation are described below;
bandwidth/deadline admission, route activation and physical-card validation
remain required.

`unsafe Otg::prepare_mpc(&mut clocks, &mut dccg, &mut gmc, pipe)` stages
opaque full-frame RGB composition for an owned DPP/surface. ColdBoot exposes
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
display/hub/VM/IRQ/clock/reset/power writers. Native header contracts are in
`tests/dcn401_mpc.c` and `tests/dcn401_requestor.c`; MMIO models cover all four
pipes, all supported RGB depths, transient buffer usage, delayed CURRENT
acknowledgements, cancellation, lost writes and stale owners. DLG/TTU and
watermark calculation/admission, MPC route connection, visible framebuffer
activation, live flips and physical RX 9070 XT validation remain open. Neither
preparation API starts fetch or publishes an active framebuffer.

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
obligations, excludes fixed-drive retimers/LTTPRs, eDP, USB-C and MST/FEC work,
and supplies the actual board/firmware PHY downspread setting. This boolean
describes existing SSC; training does not reprogram its source. No automatic
rate/lane fallback, stream enable or scanout is implied.

Training enters `TrainingDp(transmitter)` before the first AUX transaction.
It requires DPCD 1.1 or later, requests sink D0, waits at least 1 ms and checks
power readback, then reads live base/extended capabilities on the board AUX
channel. Malformed/insufficient lane/rate/coding/framing capabilities, branches,
advertised repeaters, enabled MST or FEC-ready sinks reject. An optional LTTPR
capability-block NACK is absence; timeout, protocol failure and exhausted DEFER
are errors. Native AUX retries DEFER at most six times with 1 ms delays.
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
accept only this matching streamless trained state. Sink D3 acknowledgement
precedes firmware PHY disable, independent backend/lane/TX-clock-off waits and
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
rejects impossible RGB modes but is not DML admission or a watermark proof.
Native pixel packing selects 1/2/4/8 pixels per cycle from pixel rate and DPREF.

`PreparingDpFrontend(stream)` is set before the first AUX wait. Fresh sink
configuration, D0 and per-lane/alignment checks precede writes and completion.
Setup routes the frontend symbol clock to the actual PHY, selects OTG/stereo
sources, programs uncompressed 8/10/12-bpc full-range RGB and native MSA totals,
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
are restored on every exit. Constants configure VMID0 shader access, the
single graphics pipe, eight hardware contexts and disabled GUI-idle IRQs.
The RLC image contains the six GC12 clusters (75 dwords), checked independently
against Linux's clear-state table by `tests/gfx12_clearstate.c`. Publication
retains the page through cancellation/failure; the driver programs CSIB and
enables RLC save/restore before activating four MEC stacks and unhalting PFP/ME.
An async bounded idle wait must succeed before `Report::setup` becomes valid.
This stage makes command processors available but publishes no application queue.

`amdgpu_mes12` serializes MES12's 64-dword frames using its eight-byte C
alignment, separately from MES11's four-byte alignment. It provides bounded
SET_HW_RSRC/SET_HW_RSRC_1, query-status and native kernel queue map/unmap
commands, typed completion binding and API-error decoding only after the
trailing query fence drains. Native MQDs use `v12_compute_mqd`, including
`DB_UPDATED_MSG_EN`, privileged VMID0 and the MES-owned read pointer. Descriptor,
ring, EOP and pointer ranges must be aligned, disjoint and within 48 bits;
resources never delegate VMID0 to the scheduler. `tests/mes12_layout.c` checks
these offsets against installed Linux headers.

`unsafe amdgpu_mes12_hw::Mes::new` requires exact Navi48 GC12.0.1, MMHUB4.1,
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

The platform schedules this second proof as an executor task after boot,
because framebuffer initialization may run with CPU IRQs masked. The proof
refuses MSI submission if IRQs are still masked. Diagnostics expose
`queue_state` and `queue_interrupts` separately from the historical cold-boot
report; while their owner lock is held, platform status is `Running`.

The read-only `amdgpu_dcn_inventory` routing functions support Navi48 with
GC12.0.1 and DCN4.0.1 (including raw discovery 4.1.0). ATOM display-object
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
pin pairs. Exact GC12.0.1 and DCN4.0.1/raw-4.1.0 banks are required; the
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

`unsafe amdgpu_gmc_navi48::Gmc::new` validates GC12.0.1/MMHUB4.1/NBIO banks
and the pool's BAR0/GPU mapping. `initialize().await` requires retained
firmware and trained VRAM with both hubs idle. It creates a flat VMID0 table
mapping only two owned VRAM pages in a 2 MiB aperture above physical VRAM.
Page-table and fault-default backing also lives in the owned pool; no host
DMA or user VMIDs are enabled. Both hubs must agree on framebuffer geometry.
Programming uses the GC12 fault-response fields, disables fault interrupts,
invalidates engine 17 in both hubs and the MMHUB private cache, and retains
published backing across errors/cancellation. `Ready` follows both bounded
acknowledgements, not merely table publication.

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
Overflow is a fatal event-loss condition, not silently discarded history.
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
retained monitor validates exact GC12.0.1/MMHUB4.1 banks without writes during
boot preparation. Service handoff retains all three owners before enabling
sources. It requires active, nonretrying VMID0 in both hubs, inactive user
contexts and no inherited enables in its source masks. It enables the seven
VM protection-fault classes only for VMID0, plus bad-opcode/privileged-register
faults for the owned graphics and compute pipes and privileged-instruction
faults for graphics. It also enables the graphics/compute EOP sources and
SDMA0 traps after the cold-start copy has drained; queue proofs only read
those controls, so their setup cannot race fault masking.
Readback is checked after each write. Default-page policy, user contexts and
unrelated control bits are preserved; containment leaves EOP enables intact.

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
fault or a monitor that is not armed. There is no automatic reset, PTE repair,
fault replay, user-process termination or reuse of failed allocations. SDMA,
shader, poison and media fault handling remain separate open work.

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

`unsafe amdgpu_sdma_navi48::Sdma::new` selects SDMA7.0.0/1 on GC12.0.1,
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

`display_paths(gpu, vbios)` walks `display_object_info_table_v1_4/v1_5`, resolving
DCN314, Navi22/DCN3.0 or Navi48/DCN4.0.1 from discovery. It decodes each path's
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
