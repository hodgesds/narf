# Fingerprint reader — Stage-0 scaffold

Date: 2026-05-25. Companion to `drivers/fingerprint/`.

## What landed

New crate `narf-drivers-fingerprint`:

- **VID/PID match table** — 22 entries across four vendor
  families. Sourced from libfprint's device list (BSD).
  - Synaptics Prometheus / VFS9500 (5): `06CB:00BD`, `00BE`,
    `00BF`, `00C2`, `00C9`.
  - Synaptics older Match-In-Sensor (2): `06CB:00A2`, `00B7`.
  - Goodix GF318 / GF512 (4): `27C6:5117`, `55B4`, `609C`,
    `6584`.
  - Validity / Synaptics older (6): `138A:0007`, `0011`,
    `0090`, `0091`, `0097`, `00A2`.
  - Elan (5): `04F3:0903`, `0907`, `0C03`, `0C32`, `0C42`.

- **`Family` enum** + grep-friendly `.label()` (`goodix`,
  `synaptics-prometheus`, …) for log + future routing.

- **`match_vid_pid(vid, pid)`** — linear-scan lookup; table is
  short enough that a hashmap would just add boot cost.

- **`probe_from_descriptors(device_desc, cfg_desc)`** — Stage-0
  probe entry point. Parses VID/PID at offsets 8/10 of the USB
  Device Descriptor (§9.6.1), reads `bNumInterfaces` at offset 4
  of the Configuration header (§9.6.3), matches, and on hit emits:

  ```text
    fingerprint: detected <family>:<pid> "<name>" (<N> interfaces)
  ```

  Returns the entry so Stage-1 binding can hook in.

- **`register_initcalls`** — Stage::Device initcall logs
  `match table ready (22 VID/PID entries across 4 vendors)`.

- **13 smokes** under `drivers/fingerprint`: vendor coverage,
  per-family known PIDs, random VID/PID rejection, descriptor
  edge cases, full probe flow with counter assertion, label
  format, table size, no duplicate pairs.

## What Stage-0 does NOT do (deferred)

- **No vendor protocol.** Match-In-Sensor / Match-on-Host /
  Goodix image-stream are proprietary; userspace owns them.
- **No USB interface claim.** Stage-1 hooks
  `dispatch_after_address`; matched devices currently fall
  through to `UnknownClass`.
- **No userspace surface.** Stage-2+ adds the cap-gated
  syscall for raw USB transfers.
- **No PM.** Stage-3+ adds suspend/resume.

## Source

libfprint device list at libfprint.freedesktop.org/devices.html
(BSD). NARF is GPL-2.0-or-later post 2026-05-20.
