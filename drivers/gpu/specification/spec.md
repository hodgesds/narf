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

The Phase-B VirtIO-GPU render path is layered over the existing DRM primary
and render nodes. It is deliberately small but wire-compatible with Mesa's
virtgpu userspace ABI:

- Render-node inbound: `GETPARAM`, `CONTEXT_INIT`, `RESOURCE_CREATE`,
  `RESOURCE_INFO`, `TRANSFER_{TO,FROM}_HOST`, and bounded `EXECBUFFER`.
  Handles are per-open, context creation is lazy, and opaque command streams
  are passed to a host only after size and ownership validation.
- Primary-node inbound: the existing framebuffer / modeset ioctls; an
  accelerated buffer may be presented only after it is also registered as a
  KMS framebuffer.
- Outbound: completion is synchronous for v1; the transport must not claim
  explicit-fence support until fence-fd and syncobj lifetime are implemented.
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
