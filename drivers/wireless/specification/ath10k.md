# ath10k — Specification

> Status: **Boot transport implemented; WLAN software incomplete.**
> The live PCI probe schedules an owned DMA32 CE/BMI bootstrap and obtains
> target information. This is not firmware activation or usable Wi-Fi.

## 1. Purpose & scope

PCIe Qualcomm/Atheros QCA988X, QCA6174/6164, QCA9377, QCA99X0, QCA9888
and QCA9984. AR9462 belongs to ath9k and is rejected before MMIO.
Linux `drivers/net/wireless/ath/ath10k/` is the reference implementation.

## 2. Assumptions

Probe owns the PCI function exclusively. BAR0 is mapped with device
attributes and must cover the selected RTC, core, PCI-local and CE
windows. Boot uses coherent DMA32 storage and keeps the target awake.
Boot messages are serialized and polled asynchronously; runtime IRQ and
packet service are not yet attached.

## 3. Public interface

- `register()` / `register_pci_driver()` publish exact PCI matches.
- `pci::probe` disables inherited bus mastering, wakes and identifies the
  chip, retains its metadata and schedules the boot task. Bound-driver
  presence does not mean firmware or an interface is ready.
- `pci::with_controller` exposes `Ath10kDevice` metadata.
  `target_info: Option<bmi::TargetInfo>` becomes present only after the
  real CE0 request and CE1 response complete. `boot_error` retains a
  bootstrap failure. No netdev is registered at this stage.
- `hw::HwRev::registers()` returns the correct per-family windows;
  `Registers::ce_base(pipe)` rejects an out-of-range CE index. The RTC
  chip-ID helper now returns the complete BAR-relative address.
- `ce::RingConfig` includes `hw_rev`. Sizes are **entry counts**, not byte
  counts; source DMAX and byte-swap controls preserve unrelated bits.
  `host_int_disabled` controls `HOST_IE`, never destination byte swap.
  `halt_pipe(mmio, hw_rev, pipe)` requests CMD bit 0 and waits for bit 3
  in the same command register using a bounded responsive wait.

The internal `boot::PciBoot` owns PCI authority, four coherent CE rings
(CE0 source, CE1 destination, CE7 source/destination), and request,
response and diagnostic bounce allocations. It performs Linux's reset
sequencing, CE7 host-interest/early-allocation/service-map setup, and the
target CPU interrupt before BMI. QCA988X uses the preferred warm-reset
route; it does not automatically cold-reset boards Linux documents can
hang on that path. An inherited nonempty CE fails rather than being
repointed to new host memory.

Internal `bmi::Bmi` provides target information, chunked memory read/write,
execute, zero-padded compressed download and the one-way BMI_DONE handoff.
These are wired to the owned PCI transport; firmware/board activation
does not yet call the download/DONE sequence. A retained async mutex owns
the session after target identification so no IRQ-disabling lock crosses
an await.

## 4. Invariants

- PCI parking is read back before MMIO: BME off, INTx masked, then
  memory decode enabled and verified. Additional matched singleton radios
  are parked with BME/memory decode off and rejected. BME is enabled only
  after initialization of retained rings.
- A ring slot cannot be reused until its terminal completion. Source
  completion validates the read index; RX completion reads the aligned
  16-bit count atomically and checks it against the posted capacity.
- A transaction poisons the session before its first bounce-buffer write or
  descriptor publication and clears poison only after validated completion.
  Cancellation, timeout or malformed completion retains poison. Pending DMA is
  not treated as cancelled and its backing memory is not recycled.
- Drop frees allocations only after all active boot CEs acknowledge halt
  and PCI bus-master disable is read back. A failure retains the memory.
- CPU pointers come from coherent CPU mappings; DMA addresses only enter
  device descriptors/registers. Descriptor publication and consumption
  include release/acquire ordering.
- BMI_DONE prevents further bootloader commands even if that handoff times
  out. Rounded writes and LZ tail chunks are zero-padded.
- Identity or bootloader success never enables carrier, transmit or a
  purported association.

## 5. Architecture notes

The same DMA32 and little-endian CE descriptor format is used on both NARF
architectures. The PCIe QCA99X0/9888/9984 profiles use 8-byte descriptors;
the separate 16-byte WCN3990 format is not their DMA format.

## 6. Dependencies

`bus/` supplies PCI authority and device mappings, `io/` coherent DMA32,
`lib/` the retained async mutex, and scheduler/time supply bounded waits.
Later firmware activation will consume the trusted firmware registry;
the current task does not claim arbitrary bytes as calibrated board data.

## 7. Stage assignment

Boot transport groundwork in Stage 5. Software regressions cover corrected
CE programming, ring completion/wrap/reuse, DMA bounds, BMI chunking,
short responses and the DONE transition. These tests do not emulate a
Qualcomm radio or establish reset/ROM interoperability.

## 8. Remaining software and hardware acceptance

The following are software work, not gates that a physical boot can close:

1. Firmware API container/profile parsing keyed by BMI target version;
   correct firmware paths, WMI/HTT operation versions and file lifecycle.
2. Board/OTP selection and execution, BDF and extended BDF upload,
   host-interest target configuration, clocks/PLL/UART options and the
   calibrated firmware download/DONE handoff.
3. Full runtime CE2/3/4/5 buffers and ownership, per-chip CE5 overrides,
   HIF IRQ/MSI service, recovery and PM/teardown.
4. Actual HTC credits/service handshake, family-specific WMI command and
   event operation maps, service-ready/init/ready negotiation, and the
   HTT version/descriptor/refill/TX completion/reorder paths. Existing
   standalone WMI/HTT codecs do not establish a working transport.
5. Regulatory/channel and scan/station control, management/EAPOL/key
   exchange, packet conversion, and `WirelessNetIface`/netdev registration.

After those are integrated, physical acceptance must exercise ROM/BMI,
board calibration, IRQ/DMA, scan, association, IP traffic, link loss and
reset/PM on each claimed family. Current bootstrap still needs silicon
validation; success in the offline suite does not remove the software
requirements above.
