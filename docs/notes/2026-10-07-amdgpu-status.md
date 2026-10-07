# AMDGPU status (2026-10-07)

Supersedes [`2026-05-20-amdgpu-audit.md`](2026-05-20-amdgpu-audit.md), which
is now wrong in its central claim: it names IP discovery as "the keystone
gap", and IP discovery landed, along with almost everything it listed as
downstream.

Scope of this note: what exists, what it is wired to, and what "full amdgpu
support" would still mean. Compared against `/usr/src/linux` (7.3.0-rc4).

## Size

| | |
|---|---|
| NARF `drivers/gpu/src/amdgpu*.rs` | 31,403 LOC across 82 modules (37,086 with tests) |
| Linux `drivers/gpu/drm/amd/amdgpu` | 383,431 LOC |
| Linux `drivers/gpu/drm/amd` (all) | 6,510,582 LOC |

611 kernel tests live under `drivers/gpu`.

## What is implemented and wired to boot

The live display path is **not** `AmdGpu::set_mode` — that is the original
scaffold, and its only caller is the S3 resume handler. The path that runs is:

```
Stage::Late "amdgpu-usbc"  (lib.rs)
  └─ amdgpu_usbc::start
       └─ amdgpu_platform::start
            ├─ PSP 13.0.4 GPCOM ring: install TMR, load DMCUB
            ├─ loader.boot + enable_notifications
            ├─ discover_sinks  (HPD / AUX / EDID over the DMUB mailbox)
            └─ arm → amdgpu_dcn_display::Pipeline
                 ├─ timing_from_edid
                 ├─ fixed-point DML: detile geometry, clocks, urgent /
                 │   p-state / stutter watermarks, prefetch schedule
                 ├─ program DCCG, OTG, HUBP, DPP, MPC, OPP, DP stream encoder
                 ├─ DP link training (8b/10b CR + EQ as one transaction)
                 └─ publish scanout  →  narf_fb adopts it (fb/src/lib.rs:447)
```

Also in tree and exercised by tests: IP discovery, SMU v12/v13, the ATOM
bytecode interpreter (the 2026-05-20 note recorded it as deferred), DMUB
firmware packaging and boot, VBIOS retention from ACPI VFCT or the APU VRAM
shadow, DDC/EDID, MST, HDMI audio, HPD, backlight, DPM, VCN video, GMC, VMID,
SDMA, GFX, MES, RLC, IH, reset, PCIe recovery, and USB4/DP tunnelling with
host-router bandwidth negotiation.

Platform inventory (display topology, per-connector transmitter and HPD line,
memory type/channels/data rate, DCHUB reference clock, DENTIST VCO) is read
from the board's own tables and **fails closed** when a table is missing, the
wrong revision, or self-inconsistent — it is never defaulted, because the
memory configuration multiplies into every watermark.

## What is absent

**No render path at all.** Linux's amdgpu ioctl table has 21 entries:

```
AMDGPU_GEM_CREATE  AMDGPU_CTX  AMDGPU_VM  AMDGPU_SCHED  AMDGPU_BO_LIST
AMDGPU_FENCE_TO_HANDLE  AMDGPU_GEM_MMAP  AMDGPU_GEM_WAIT_IDLE  AMDGPU_CS
AMDGPU_INFO  AMDGPU_WAIT_CS  AMDGPU_WAIT_FENCES  AMDGPU_GEM_METADATA
AMDGPU_GEM_VA  AMDGPU_GEM_OP  AMDGPU_GEM_USERPTR  AMDGPU_USERQ
AMDGPU_USERQ_SIGNAL  AMDGPU_USERQ_WAIT  AMDGPU_GEM_LIST_HANDLES
AMDGPU_PROC_OPTIONS
```

NARF dispatches none — `drm_ioctl_bridge.rs` does not contain the string
`amdgpu`. The modules they need (`amdgpu_cs`, `amdgpu_bo`, `amdgpu_ttm`,
`amdgpu_fence`, `amdgpu_sched`, `amdgpu_ib`) do not exist. Mesa's radeonsi
calls `AMDGPU_INFO` as its first act, so there is no path to GL or Vulkan on
AMD, and no `libdrm_amdgpu` consumer can open the render node.

**`AmdgpuCard` is metadata-only.** The `DrmCard` trait
(`drm_registry.rs:33`) is nine methods — name, driver, PCI ids, VBIOS
version, busy percent, power state. No CRTC, connector, plane, framebuffer or
flip. So `/dev/dri/card0` on an AMD machine publishes sysfs identity, and the
KMS ioctls are served by the generic `drm::card::Card` against the `narf_fb`
scanout. The native pipeline above reaches the display by *publishing a
scanout the framebuffer layer adopts*, not by backing the KMS object model.
Joining those two is what would let a KMS client drive real DCN outputs.

**It has never run on silicon.** Every test runs under QEMU, which exposes no
AMD GPU, and `probe()` rejects non-AMD vendors. So the watermarks, prefetch
deadlines, link training and PSP sequencing are all unconfirmed against
hardware. `STATUS.md` says the same in as many words: "The one remaining gap
is silicon."

## What "full support" would mean, in two sizes

1. **Unaccelerated desktop on an AMD laptop** — mostly joining what exists:
   back the KMS object model with the DCN pipeline so `GETRESOURCES` /
   `SETCRTC` / `PAGE_FLIP` reach real connectors and planes, and then run the
   Stage 5 laptop gate. Bounded.
2. **Accelerated desktop** — the GEM/VA/CS/fence/scheduler stack plus those
   21 ioctls plus `libdrm_amdgpu` compatibility. A long arc, and not required
   for a software-rendered desktop.

## Corrections to the 2026-05-20 note

1. "IP discovery is the keystone" — landed; `amdgpu_discovery.rs` is 490 LOC
   and `ip_block_base` is the lookup everything uses.
2. "ATOMBIOS bytecode interpreter explicitly deferred" — landed;
   `amdgpu_atom_vm.rs` is 1,471 LOC.
3. "`set_mode` is a TODO stub" — it exists, but it is the wrong entry point to
   reason about; see the live path above. It carries a three-entry timing
   table (1920x1080, 1366x768, 1280x720 @60) that the live path does not use,
   since `timing_from_edid` derives timing from the sink.
4. "~3,400 LOC across 11 files" — now 31,403 across 82.
