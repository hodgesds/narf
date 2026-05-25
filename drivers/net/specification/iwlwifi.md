# iwlwifi — Specification

> Status: **v0.2** (Stage 2: CSR map + APM init + ucode header
> decode + probe + log; firmware-load + alive-handshake are Stage 3).
>
> GPL-2.0-or-later driver for Intel Wi-Fi 6 / 6E PCIe host
> controllers (AX200 / AX201 / AX210 / AX211 / AX411 + Killer 1690).
> Adapted directly from Linux `drivers/net/wireless/intel/iwlwifi/`
> source — NARF was relicensed to GPL-2.0-or-later on 2026-05-20,
> unblocking the prior clean-room constraint.

## 1. Purpose & scope

**Owns:** Bring-up of Intel AX2xx-class Wi-Fi 6 / 6E radios
attached over PCIe. Stage 1 lands only the PCI vendor/device
match table — no MMIO access, no firmware load.

**Does NOT own (any stage):** mac80211-equivalent stack,
802.11 frame parsing/building (lives in `narf_net`), regulatory
domain handling.

## 2. What the public docs cover

The following surface is openly published and forms the entire
foundation we have to work from:

- **PCI vendor/device IDs.** Vendor `0x8086` (Intel). Devices:
  - `0x2723` — AX200 (Wi-Fi 6, Gig+).
  - `0x02F0` — AX201 (Wi-Fi 6, CRF/CNVio).
  - `0x2725` — AX210 (Wi-Fi 6E).
  - `0x51F0` — AX211 (Wi-Fi 6E, CRF/CNVio).
  Sourced from the Intel "Wi-Fi 6 (Gig+) AX200/AX201" and
  "Wi-Fi 6E AX210/AX211" product briefs + Intel ARK.
- **Per-part product briefs.** Cover supported PHY rates, channel
  bandwidths (20/40/80/160 MHz), MIMO config (2x2), spatial
  streams, BT coexistence, OFDMA / MU-MIMO support flags. Useful
  for advertising capabilities to an upper stack but irrelevant
  to bring-up.
- **PCIe capability headers.** Standard config-space surface:
  Vendor/Device, MSI-X capability pointer, BAR layout (single
  64-bit MMIO BAR at BAR0), power-management capability. This
  is fully decoded by `narf-bus` already and gives us BAR0's
  physical address + size. Nothing in this surface is
  iwlwifi-specific.
- **IEEE 802.11.** The MAC + PHY *protocol* layer above the
  hardware. Says nothing about how to *talk to* an Intel radio.

## 3. The wall — what is NOT public

Beyond the PCI ID and BAR0 address, every byte of the
operational interface is undocumented in any source we are
permitted to consult:

- **CSR (Control / Status Register) offsets.** The block at the
  bottom of BAR0 used to reset the device, gate the firmware
  load, and signal device readiness. Offsets, bit fields, and
  reset sequence: not in any Intel public doc.
- **PRPH (peripheral) register window.** The indirect-access
  register file behind a window pair in CSR. Offsets, semantics,
  per-family layout differences: undocumented publicly.
- **Firmware load protocol.** The AX2xx parts run an Intel-
  signed firmware blob that the host pushes through a sequence
  of CSR writes + DMA transfers. The protocol (sections, hash
  verification, alive-notification handshake) is undocumented;
  the firmware blobs themselves are redistributable but the
  loader code is not.
- **TFD (Transmit Frame Descriptor) layout.** The DMA descriptor
  format on the TX path. Field offsets, ownership bits, scatter-
  gather chaining: undocumented.
- **RBD (Receive Buffer Descriptor) layout.** Same problem on
  the RX side.
- **Host commands.** The opcode + payload format the driver
  uses to drive scan / associate / key install / etc. Each
  family revision (7000 / 8000 / 9000 / 22000-series) has a
  different command set; none are publicly documented.
- **MQ / Multi-Queue command/response rings.** AX210 / AX211
  use a different command-ring shape than AX200 / AX201; the
  shape itself is undocumented.

The only public source for any of the above is the GPL-licensed
Linux `drivers/net/wireless/intel/iwlwifi/` tree, which we have
explicitly excluded from this work.

## 4. Stage 1 (this stage) — what landed

- PCI match table at `drivers/net/src/iwlwifi.rs` covering the
  four AX2xx device IDs.
- Probe stub records the device in `narf-drivers::record_bound`
  so the boot inventory shows the part was seen, then returns
  `Ok(())` without touching BAR0.
- Smoke at `drivers/net/src/iwlwifi/tests.rs` asserts all four
  match entries land in the bus driver registry.

## 5. Stage 2 (this stage) — spec doc

This document. No new code beyond Stage 1.

## 6. Future stages — blocked

The following are the natural next stages if and when public
docs become available:

- **Stage 3 (blocked).** CSR reset sequence + device-ready
  poll. Requires the CSR offset map.
- **Stage 4 (blocked).** Firmware image load. Requires the
  loader protocol *and* shipping the Intel-signed firmware
  blob — the firmware itself is redistributable from Intel's
  linux-firmware repo, but the loader code path is not
  documented.
- **Stage 5 (blocked).** Alive-notification handshake. Requires
  the MQ command/response ring layout + alive-notification
  format.
- **Stage 6 (blocked).** Scan + associate. Requires the host-
  command opcode set for the target family.
- **Stage 7 (blocked).** TX/RX fast path. Requires the TFD/RBD
  descriptor layout + host-command layouts for key install.

Until those layouts are public, this driver remains at
"structural probe only."

## 7. Non-paths

Two avenues are explicitly **not** taken here:

1. **Reading the GPL Linux iwlwifi source.** Out of scope per
   project policy — this is a clean-room build. Where the public
   docs are silent we leave a `TODO(iwlwifi-public-docs)`
   comment and stop.
2. **Reverse-engineering from a running device.** Possible in
   principle (capture the loader on real silicon, dump CSR
   accesses) but a non-trivial undertaking that belongs in its
   own project with its own clean-room provenance trail.

## 8. References

- Intel "Wi-Fi 6 (Gig+) AX200" product brief (public PDF).
- Intel "Wi-Fi 6E AX210" product brief (public PDF).
- Intel ARK SKU pages (AX200 / AX201 / AX210 / AX211 / BE200).
- IEEE Std 802.11-2020 (open standard).
- PCI Express Base Specification — capability-header layout.

## 9. 2026 web-search audit — confirmation of the wall

A targeted web search re-ran in 2026 to look for any new public
material covering the AX2xx / BE200 register set or firmware
command interface returned **nothing past the marketing briefs
already cited above**. Specifically:

- Intel does **not** publish a register manual, an NVM section
  format spec, a CSR/UREG bitfield table, or an MVM ucode ABI
  document for any part in the AX family.
- The `iwlwifi/linux-firmware` repository at git.kernel.org
  ships only signed binary blobs.
- The Fuchsia / Zircon `third_party/iwlwifi` port reads the
  command interface from the upstream **GPL-2.0** Linux source,
  so it is not a clean-room reference.

→ Confirmation that the v0.1 verdict still stands: PCI ID match
plumbing is the only stage that can land without consulting GPL
sources or signing an Intel NDA. The driver remains stub-only.
