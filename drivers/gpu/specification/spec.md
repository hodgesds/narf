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
`Config::requirements` returns DISPCLK, DPPCLK and the deep-sleep DCFCLK floor
already rounded to frequencies the DFS dividers can produce, plus the plane's
read bandwidth. DISPCLK keeps DML's ramping margin where the DPM ceiling allows
it and drops to the unramped requirement otherwise, so no mode is refused for a
margin; a requirement above the ceiling is reported rather than clamped, leaving
the refusal to the caller. Bandwidth, watermark and prefetch derivation, and the
RQ/DLG/TTU register encoding, are not implemented yet.

Neither the attach worker nor a booted loader **programs the stream pipeline or
exposes new active DRM/KMS scanouts**. A successful firmware boot, sink read,
trained link, clock update or mode calculation does not prove monitor output:
watermark and prefetch derivation, RQ/DLG/TTU encoding, the DCCG dividers, OTG
timing, the HUBP/DPP/MPC/OPP pipeline, the DIG stream encoder, scanout
allocation and KMS attachment remain open, and no code path yet lights an
external panel.
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
  `RESOURCE_FLUSH` rather than copied through the boot 2D resource. On a
  primary-node open, VIRTGPU-created handles are registered in the same GEM
  namespace consumed by ADDFB2; render and KMS handles on one `drm_file` must
  never diverge. DRM command words use the exact Linux UAPI structure sizes;
  in particular `GEM_CLOSE` is the 8-byte `0x40086409` request so it reaches
  that per-open teardown path before generic KMS cleanup.
- Primary-node inbound: the existing framebuffer / modeset ioctls; an
  accelerated buffer may be presented only after it is also registered as a
  KMS framebuffer. `PAGE_FLIP_EVENT` completions are bound to the submitting
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
  `FENCE_FD_OUT` sync-file, and binary output syncobjs. `VIRTGPU_WAIT`, poll,
  input fence fds, and foreign-context input syncobjs observe that real device
  completion; dependencies on the same ordered context/ring do not serialize
  submission. Descriptor exhaustion returns `EMFILE` before GPU work is
  queued. EXECBUFFER syncobj records accept binary point zero and the input
  RESET flag; non-zero timeline points remain unsupported.
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
