# ath9k — Specification

> Status: **AR9285 reset/EEPROM identity implemented; radio software
> incomplete.** No network interface or packet DMA is enabled.

## 1. Purpose & scope

The currently matched PCIe part is AR9285 (`168c:002b`). Broader ath9k
families are not implemented merely because Linux supports them.
This is a soft-MAC radio: unlike ath10k it does not use a downloadable
WLAN firmware to supply MLME and hardware programming.

## 2. Assumptions

The PCI dispatcher grants exclusive function authority. Probe disables
inherited bus mastering, enables memory decode and masks INTx before
mapping a device-typed BAR0 covering registers through `0x704f`.
AR9285-specific writes follow a checked silicon revision.

## 3. Public interface

- `register()` installs the AR9285 PCI match.
- `probe()` reads the complete factory calibration image after Linux's
  bounded power-on/warm-reset sequence. It retains the controller instead
  of constructing and immediately discarding an `Arc`.
- `with_controller()` provides read-only `Ath9k` inspection.
- `Ath9k::identity` exposes the silicon revision, validated unicast MAC,
  EEPROM version, factory regulatory-domain values, and chain masks.
- `Ath9k::calibration()` exposes the complete 376-byte normalized
  `ar5416_eeprom_4k` image for later PHY calibration programming.
- Errors distinguish absent/mismatched silicon, timeout, invalid EEPROM
  magic/length/checksum/version, and invalid factory identity.

The former reset-only `Ath9k::new` constructor is removed. Construction
goes through the PCI authority and identification path. Successful probe
records hardware identity; it does not register a netdev or imply a WLAN.

## 4. Invariants

- PCI parking is verified by command-register readback before MMIO: BME
  off and INTx masked, followed by verified memory-decode enable. Additional
  matched singleton radios are parked with BME/memory decode off and rejected.
- BME remains disabled throughout identification. Interrupts remain
  masked; no unowned DMA rings can run.
- Register and EEPROM waits use the scheduler's bounded responsive wait;
  reset settling delays are measured in time, not CPU iteration counts.
- EEPROM reads trigger by reading `0x2000 + word * 4` and accept data only
  after the status busy/protection bits clear. Word indices are bounded.
- The map starts at EEPROM word 64 and has 188 words. Magic-driven word
  normalization precedes EEPROM-field endianness handling; checksum is
  validated over the declared bounded even length. Version major 14 and
  minor at least 1 are required.
- Factory MAC is nonzero/unicast and AR9285 chain masks are single-chain.
  Factory regulatory identifiers do not themselves grant transmit rights.

## 5. Architecture notes

The register protocol is shared by both NARF architectures. Byte-order
normalization covers ordinary, word-swapped and big-endian-field EEPROM
images. The 376-byte layout was checked against the packed structs from
local Linux `ath9k/eeprom.h`.

## 6. Dependencies

PCI authority and MMIO come from `bus/`, retained state from `lib/`, and
responsive waits from scheduler/time. No packet-DMA allocation is made.

## 7. Stage assignment

Stage 5 identification prerequisite. Traced smokes exercise the live
identification helper, complete EEPROM extent, reset register order,
endianness/checksum/version validation and invalid/busy hardware cases.
They do not prove RF or packet operation.

## 8. Remaining software and physical acceptance

Software still required before AR9285 is ready for physical Wi-Fi testing:

1. AR9002/AR9285 MAC/baseband/analog initialization tables, PLL and PCIe
   power-save setup, EEPROM modal/power/antenna/CTL application, RF channel
   synth programming, noise-floor/IQ/PA calibration and regulatory limits.
2. Real TX queue/RX descriptor allocations and DMA ownership, IRQ service,
   TX completion, RX status/decryption/replay/error handling, and complete
   stop/reset/hot-remove/PM lifecycle before any memory can be reclaimed.
3. Soft-MAC station management, authenticated scan/channel state,
   management and data TX/RX, rate/retry/aggregation state, EAPOL/key
   handling, and a real `WirelessNetIface`/netdev data path.

Other ath9k devices need their own EEPROM maps, reset/PHY tables and
descriptor/runtime variants before they can be claimed supported.
Physical acceptance then covers EEPROM, RF calibration, channel/IRQ/DMA,
scan/association/IP traffic, link loss, reset and power transitions.
