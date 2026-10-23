# Broadcom FullMAC PCIe — software bring-up

> Status: v0.3. PCI ownership and AI core discovery are implemented.
> Firmware bootstrap and a live msgbuf station are software work still required.

## 1. Purpose & scope

Owns Broadcom PCIe FullMAC (`brcmfmac`) device ownership, chip discovery,
firmware bootstrap, shared-memory/msgbuf transport, and station integration.
SDIO CYW43439 uses the separate [CYW43439 contract](cyw43439.md).

## 2. Assumptions

PCI matching identifies a candidate, not a validated chip or usable radio.
AI/AMBA ChipCommon is at 0x18000000. The PCIe BAR0 window selects a
4-KiB backplane page through PCI configuration offset 0x80. CPU, RAM,
firmware, and board-data decisions must use discovered chip/revision
information rather than equating the PCI device ID with the chip ID.

## 3. Public interface

`pcie::probe(BusDevice, Cap<BusDeviceCap, Write>)` retains exclusive PCI
authority in a parked controller. `unsafe pcie::bring_up(device, cap)`
requires exclusive BAR/config ownership and returns that same owned state.
Both paths first clear inherited `BUS_MASTER`, enable `MEM_SPACE` and
`INTX_DISABLE`, verify DMA is disabled, and validate BAR0 before access.
The control BAR mapping ignores a firmware-provided prefetchable attribute.
They publish a bound-driver inventory entry, not a network interface.

`chip::Backplane` supplies serialized fallible `read32`/`write32` operations.
The production PCIe implementation keeps the BAR and capability private;
each access validates alignment/range, selects the page, and verifies
readback with at most one retry. The configuration helpers check current
capability validity for every select. `Chip::discover` reads the actual
chip ID/revision, walks bounded AI EROM descriptors, and returns discovered
`Core { id, revision, base, wrapper }` records. It performs no writes.
Non-AI interconnects and malformed/out-of-range maps are rejected.

`Chip::park_pcie` masks the PCIe interrupt and mailbox sources before
acknowledging the sampled mailbox status. PCIe core revisions below 64
use offsets 0x24/0x48/0x4c; revisions 64 and above use 0xc14/0xc30/0xc34.
Those offsets are relative to the discovered core, independently of the
firmware shared-memory version. This is interrupt parking, not a reset.

The existing `msgbuf`, `ringbuf`, `fwil`, `fweh`, `shared`, `firmware`,
`cfg80211`, and `connect` interfaces contain wire/cursor helpers or
attachment models. None supplies a live DMA/firmware owner or permits
publishing a usable station yet. In particular `connect_wpa2_psk` is an
orchestration model without a complete key-installation lifecycle.

## 4. Invariants

- No bus mastering without owned DMA mappings, ring lifetimes, and a
  terminal cleanup/reset path. Probe leaves it disabled even on errors.
- Window selection and the subsequent MMIO access have one mutable owner.
  Raw BAR handles are not exposed to concurrent clients.
- Discovery consumes at most 1024 EROM words and retains at most 64 cores.
  Extended address/size descriptors are consumed; a nonzero high address
  word is never truncated into a 32-bit address. Selected register and
  wrapper pages must lie in 0x18000000..0x20000000.
- A map must contain ChipCommon at its expected base and exactly one PCIe2
  core. Duplicate register bases and partial component descriptors fail.
- A gone-device all-ones status is never acknowledged as a live mailbox.
- No await or hardware wait may hold the static controller's IRQ lock.
  Subsequent async firmware/runtime work must move ownership out or use
  an async mutex and scheduler deadlines.

## 5. Architecture notes

The register protocol is architecture independent. `MmioRegion` provides
volatile access and architecture barriers; PCI configuration uses the
capability-checked bus helpers. AI discovery model tests run on both
x86_64 and aarch64; passing them does not establish physical operation.

## 6. Dependencies

Implemented dependency: PCI enumeration, exclusive capability, BAR mapping.
Remaining software dependencies, in activation order:

1. Chip CPU passive/reset controls, bank-derived RAM discovery, chip quirks,
   and owned BAR2 TCM mapping with checked extents.
2. Signed chip/revision/board-specific firmware and NVRAM selection,
   NVRAM padding/token construction, firmware upload/reset-vector start,
   and deadline-bounded shared-memory pointer handshake. Newer Apple OTP
   board selection and newer firmware metadata must be handled explicitly.
3. Validated shared/ring-info addresses and feature negotiation; IOMMU/DMA
   ownership; common-ring allocation/index visibility; MSI/doorbell work;
   correlated IOCTL responses and provisioned event/IOCTL/RX buffers.
4. Flow-ring create/delete/completion ownership, TX reclamation, RX
   validation, bounded poll/workers, and recovery/reset cleanup.
5. Regulatory/CLM attachment; live scan and association; firmware key and
   authorization events; Ethernet/control-port admission; NARF frame rings
   and wireless registry publication; disconnect/rekey/recovery replay.

These are implementation blockers, not physical-only validation gates.

## 7. Stage assignment

Stage 5 software bring-up. No hardware readiness claim follows from the
PCI match inventory, protocol encoders, or synthetic discovery tests.

## 8. Verification and open questions

Regression fixtures exercise the production `Chip::discover` and
`park_pcie` paths using literal Linux-format descriptors. They cover
different discovered PCIe core bases, the revision-64 interrupt-layout
boundary, extended address/size words, aliased/missing cores, invalid
EROM pointers, malformed pairs, absent termination, and gone mailboxes.

Primary references: `/usr/src/linux/drivers/net/wireless/broadcom/brcm80211/`
`brcmfmac/chip.c`, `pcie.c`, `firmware.c`, `msgbuf.c`, `commonring.c`, and
`include/brcm_hw_ids.h` in the same source tree. Actual board firmware and
silicon acceptance remain after the software dependencies above.
