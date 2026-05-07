# drivers/gpu/nvidia_gpu — Specification (stub)

> Status: **v0.1** (planning stub — no driver code yet).
>
> Clean-room driver for NVIDIA discrete + integrated GPUs from
> Turing through Ada Lovelace, using the publicly-released open
> documentation set. **No GPL Linux `nouveau` source consulted.**
> The `open-gpu-kernel-modules` MIT-licensed portion is consulted
> directly; GPL-2.0 files in that tree are explicitly excluded.

## 1. Coverage

| Generation                | open-gpu-doc coverage        | Verdict        |
| ------------------------- | ---------------------------- | -------------- |
| Turing (TU10x)            | Full register listings       | Feasible       |
| Ampere (GA10x)            | Full register listings       | Feasible       |
| Ada Lovelace (AD10x)      | Partial — most blocks public | Feasible       |
| Hopper (compute)          | Compute classes partial      | Compute-only feasible |
| Blackwell (GB20x)         | Not in open-gpu-doc as of mid-2026 | Wait    |

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

## 3. Stage plan (when started)

### Stage 1 — Stub
- `nvidia_gpu.rs` + this spec: PCI vendor 0x10DE, class 0x03,
  match table for documented Turing / Ampere / Ada parts.
- Pull device IDs from the public NVIDIA `gpus.h` table (the
  table itself is MIT-licensed).

### Stage 2 — Display-only on Turing
- GSP firmware staging via the documented loader (the loader
  protocol is in the MIT-licensed portion of open-gpu-kernel-
  modules; the GSP firmware blob is opaque).
- Display engine init + DP output via the existing
  `graphics/dp_aux` + `graphics/dp_psr` codecs.
- Mode-set per the Turing display register reference.

### Stage 3 — Frame buffer
- BAR1 instance memory mapping, BAR2 page-table walks, scanout
  surface allocation through the documented FIFO subchannels.

### Stage 4+ — Command streamer / compute
- Push-buffer protocol + GR class instantiation via the open-
  gpu-doc method tables.
- Out of scope for v1 (display surface is enough for a kernel-
  resident driver).

## 4. Out of scope

- Blackwell — wait for open-gpu-doc.
- Display-side video acceleration (NVENC / NVDEC) — separate
  hardware classes documented in their own open-gpu-doc subdir;
  defer until base driver is up.
- The full RM IPC surface to the GSP — only the subset needed
  for display + scanout lands in v1.
