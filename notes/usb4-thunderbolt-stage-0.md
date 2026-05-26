# USB4 / Thunderbolt — Stage-0 NHI scaffold

Date: 2026-05-25. Companion to `drivers/thunderbolt/`.

## What landed in Stage-0

One new crate, three integration edits.

1. **`drivers/thunderbolt/`** — new crate, `narf-drivers-thunderbolt`.
   - **`nhi::TB_DEVICE_IDS`** — 22-entry match table for the Intel
     client + discrete Thunderbolt / USB4 NHI device IDs. Sourced
     from `nhi_ids[]` in Linux `drivers/thunderbolt/nhi.c` (post-
     2026-05-20 relicense — direct GPL-2.0-or-later citation per
     `feedback_no_gpl_links`). Coverage: Tiger Lake (user-cited
     0x9A1B / 0x9A1D Maple Ridge), Alder Lake (0x463E / 0x463F /
     0x466D), Raptor Lake / Meteor Lake (0xA73E / 0xA76D / 0x7EB2
     / 0x7EB3 / 0x7EC2 / 0x7EC3), Lunar Lake (0xA833 / 0xA834),
     Panther Lake, Wildcat Lake, Barlow Ridge 80G / 40G accessory
     hubs (0x5781 / 0x5784).
   - **`nhi::Nhi::bring_up`** — maps BAR0 (NHI MMIO), reads
     `REG_CAPS` at 0x39640, extracts version (23:16) + hop count
     (10:0). Constants match `drivers/thunderbolt/nhi_regs.h`.
   - **Probe** — flips `MEM_SPACE | BUS_MASTER`, calls `bring_up`,
     emits `thunderbolt: detected <sku> BAR0=<base>, NHI
     version=<v>, <N> adapter ports`, records under
     `BoundKind::UsbHost`.
   - **Stage::Device initcall** — registered in
     `frame/src/bare_main.rs` next to storage / USB initcalls;
     Stage::Device is where `probe_all_pci` binds drivers.

2. **`drivers/thunderbolt/src/tests.rs`** — seven smokes: match-
   table coverage of every known DID, synthetic 0x9A1B matches at
   full specificity, probe rejects unrelated Intel with
   `NotForThisDriver`, `REG_CAPS` layout sanity vs. Linux,
   `sku_name` round-trip, brief-cited DIDs present, and QEMU TCG
   `not-present` counter-evidence.

## What Stage-0 does NOT do (deferred)

- No CM mailbox / ring-0 control packet bring-up.
- No XDomain topology walk or route-string assembly.
- No PCIe / DP tunnelling, no IOMMU / DMA-remap, no CL0s / CL1 /
  CL2 power-state management.
- No AMD USB4 controller coverage — Intel-only at Stage-0.

## Source citation

`drivers/thunderbolt/nhi.c` (`nhi_ids[]`) and `nhi_regs.h`
(`REG_CAPS`, version mask, hop-count mask) — direct adaptation
allowed under the post-2026-05-20 GPL-2.0-or-later relicense.
