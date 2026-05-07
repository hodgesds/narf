# drivers/gpu/nvidia_gpu — Specification

> Status: **v0.5** (Stage 1 + 2 codecs landed: PCI claim, PMC,
> Falcon, GSP RPC, host FIFO, display engine).
>
> Clean-room driver for NVIDIA discrete + integrated GPUs from
> Turing through Ada Lovelace, using the publicly-released open
> documentation set. **No GPL Linux `nouveau` source consulted.**
> The `open-gpu-kernel-modules` MIT-licensed portion is consulted
> directly; GPL-2.0 files in that tree are explicitly excluded
> (each consumed file's SPDX header is checked).

## 1. Coverage

| Generation                | open-gpu-doc coverage              | Verdict               |
| ------------------------- | ---------------------------------- | --------------------- |
| Turing (TU10x)            | Full register listings             | Feasible              |
| Ampere (GA10x)            | Full register listings             | Feasible              |
| Ada Lovelace (AD10x)      | Partial — most blocks public       | Feasible              |
| Hopper (compute)          | Compute classes partial            | Compute-only feasible |
| Blackwell (GB20x)         | Not in open-gpu-doc as of mid-2026 | Wait                  |

## 2. Public reference set

- **NVIDIA `open-gpu-doc` repository** — the canonical hub. Per-
  chip subdirectories carry `dev_*.ref.txt` register listings.
  <https://github.com/NVIDIA/open-gpu-doc>
- **Web-rendered version** of the same content.
  <https://nvidia.github.io/open-gpu-doc/>
- **NVIDIA `open-gpu-kernel-modules`** (dual MIT / GPL-2.0). The
  narf driver consumes the **MIT-licensed files only** — the
  RM headers describing the GSP firmware command interface live
  in the MIT-licensed portion. Each file's SPDX header is
  checked before consumption.
  <https://github.com/NVIDIA/open-gpu-kernel-modules>
- **Public `pci.ids` database** — every NVIDIA device ID this
  driver recognises is sourced from the upstream snapshot.

## 3. Reference map

Every register / constant cited in a `nvidia_gpu_*` module names
its source file in a doc-comment. The following are the
canonical files consulted (all in the cited repos):

| Module                  | Public source                                      |
| ----------------------- | -------------------------------------------------- |
| `nvidia_gpu_pmc`        | `open-gpu-doc/.../dev_pmc.ref.txt`                |
| `nvidia_gpu_falcon`     | `open-gpu-doc/.../dev_falcon_v4.ref.txt`          |
| `nvidia_gpu_gsp`        | `open-gpu-kernel-modules/.../include/gsp/...` (MIT-licensed RPC headers) |
| `nvidia_gpu_fifo`       | `open-gpu-doc/.../dev_pbdma.ref.txt` + Turing host class spec |
| `nvidia_gpu_disp`       | `open-gpu-doc/.../dev_disp_v04_00.ref.txt`        |

The license / SPDX-header check rule:

- Files in `open-gpu-doc` are MIT-licensed top-to-bottom; safe to
  consume for register names, offsets, and bit-fields.
- Files in `open-gpu-kernel-modules` carry per-file SPDX. Only
  files marked `MIT` (the `nvidia/inc` / `nvidia/inc/hw` /
  `common/inc` headers describing RPC structures) are consumed.
  GPL-2.0 files in that tree (the kernel-side `nv-kernel.o`
  glue, `os/posix/...` helpers) are excluded.

## 4. Stage plan

### Stage 1 (landed) — PCI claim + presence test
- `nvidia_gpu.rs`: vendor `0x10DE`, class `0x03`, match table for
  documented Turing / Ampere / Ada parts plus a class-match
  backstop that filters on vendor.
- BAR0 maps the unified register window (also called
  "instance memory aperture" in NVIDIA's docs); BAR1 maps the
  GPU-visible system memory aperture; BAR3 (or BAR2 on some
  parts) carries the framebuffer aperture for discrete cards.
- Presence test by reading `NV_PMC_BOOT_0` (BAR0 offset 0). All-
  ones means the BAR is mapped but no silicon backs it.
- Architecture is decoded from `NV_PMC_BOOT_0` bits[28:20];
  Turing / Ampere / Ada / Hopper return distinct numeric tags.
- Records `BoundDriver { name: "nvidia-gpu", kind: Graphics }`
  on successful probe.

### Stage 2 (landed) — Codec layer
- **`nvidia_gpu_pmc`** — PMC (Master Control) register block:
  `NV_PMC_BOOT_0` decoder (architecture / implementation /
  major / minor / revision fields), `NV_PMC_ENABLE` per-engine
  bits, `NV_PMC_INTR_*` mask layout. Source: open-gpu-doc
  `dev_pmc.ref.txt`.
- **`nvidia_gpu_falcon`** — Falcon CPU register codec — generic
  across every NVIDIA microcontroller the host driver brings up
  (PMU, SEC2, GSP, GPCCS): `CPUCTL`, `BOOTVEC`, `IMEMC` /
  `IMEMD`, `DMEMC` / `DMEMD`, `IRQSTAT`, `BOOTROM_RESET`,
  `MAILBOX0` / `MAILBOX1`. Source: open-gpu-doc
  `dev_falcon_v4.ref.txt`.
- **`nvidia_gpu_gsp`** — GSP RPC message framing: 16-byte
  header (function, length, sequence, status) + variable
  payload, plus the documented "send RPC" function IDs the host
  uses for display bring-up. Source: MIT-licensed RPC headers
  in open-gpu-kernel-modules (each consumed file's SPDX
  header verified).
- **`nvidia_gpu_fifo`** — Host FIFO push-buffer codec for
  Turing+: 64-bit GPFIFO entry layout (`GP_ENTRY0` get-pointer
  low + `GP_ENTRY1` get-pointer high + length + flags),
  method-cell encoding (subchannel × method-addr × parameter
  count), USERD doorbell layout. Source: open-gpu-doc
  `dev_pbdma.ref.txt` + Turing host-class spec.
- **`nvidia_gpu_disp`** — Turing+ display engine register
  layout: head / window / cursor block bases, raster timing
  cells (`HEAD_RG_SIZE_RASTER`, `HEAD_FRONT_PORCH`,
  `HEAD_SYNC_END`), Output Resource (OR) protocol selectors
  (DP-SST / DP-MST / HDMI / DSI). Source: open-gpu-doc
  `dev_disp_v04_00.ref.txt`.

Codec layer is transport-agnostic — produces register
addresses + value encodings. Stage-3 driver core consumes them
through the standard MMIO indirection.

### Stage 3 (future) — Display-only on Turing
- GSP firmware staging via the documented loader (the loader
  protocol is in the MIT-licensed portion of open-gpu-kernel-
  modules; the GSP firmware blob is opaque).
- Display engine init + DP output via the existing
  `graphics/dp_aux` + `graphics/dp_psr` codecs.
- Mode-set per the Turing display register reference + the
  Stage-2 codec.

### Stage 4 (future) — Frame buffer
- BAR1 instance memory mapping, BAR2 page-table walks, scanout
  surface allocation through the documented FIFO subchannels.

### Stage 5+ (future) — Command streamer / compute
- Push-buffer protocol + GR class instantiation via the open-
  gpu-doc method tables.
- Out of scope for v1 (display surface is enough for a kernel-
  resident driver).

## 5. PCI device ID table

NVIDIA Turing / Ampere / Ada device IDs sourced from the public
**`pci.ids`** database, cross-referenced against the MIT-
licensed `gpus.h` index in `open-gpu-kernel-modules`. The list
is representative — popular SKUs across Turing / Ampere / Ada;
unlisted parts fall through the class-match backstop.

| Device ID | Marketing                                 |
| --------- | ----------------------------------------- |
| 0x1E04    | TU102 — RTX 2080 Ti                       |
| 0x1E07    | TU102 — RTX 2080 Ti (refresh)             |
| 0x1E81    | TU104 — RTX 2080 Super                    |
| 0x1E82    | TU104 — RTX 2080                          |
| 0x1F02    | TU106 — RTX 2070                          |
| 0x1F08    | TU106 — RTX 2060 Rev. A                   |
| 0x2204    | GA102 — RTX 3090                          |
| 0x2206    | GA102 — RTX 3080                          |
| 0x2484    | GA104 — RTX 3070                          |
| 0x2503    | GA106 — RTX 3060                          |
| 0x2684    | AD102 — RTX 4090                          |
| 0x2786    | AD103 — RTX 4070 Ti                       |
| 0x2882    | AD104 — RTX 4070 (laptop)                 |
| 0x2820    | AD104 — RTX 4080 (laptop)                 |

A class-match backstop (`MatchKind::Class { class: 0x03,
mask: 0xFF }`) catches every PCI VGA controller; the probe body
filters on `vendor == 0x10DE` so AMD / Intel / virtio-gpu cards
fall through to their own drivers.

## 6. Out of scope

- Blackwell — wait for open-gpu-doc.
- Display-side video acceleration (NVENC / NVDEC) — separate
  hardware classes documented in their own open-gpu-doc subdir;
  defer until base driver is up.
- The full RM IPC surface to the GSP — only the subset needed
  for display + scanout lands in v1.
- Pre-Turing parts (Maxwell, Pascal, Volta) — open-gpu-doc
  carries them but they predate the GSP-driven flow; their
  bring-up is a different code path and not on the Stage 3+
  roadmap.
- HDCP / content-protection registers — out of scope for the
  KMS-grade driver.
