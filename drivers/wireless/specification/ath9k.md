# ath9k — Specification

> Status: **AR9285 reset/EEPROM and inactive baseband preparation
> implemented; radio software incomplete.** No network interface, PHY
> activation or packet DMA is enabled.

## 1. Purpose & scope

The currently matched PCIe part is AR9285 (`168c:002b`). Broader ath9k
families are not implemented merely because Linux supports them.
This is a soft-MAC radio: unlike ath10k it does not use a downloadable
WLAN firmware to supply MLME and hardware programming.

## 2. Assumptions

The PCI dispatcher grants exclusive function authority. Probe verifies
inherited bus mastering and memory decoding are off with INTx masked.
BAR sizing/mapping runs within the capability invocation while decoding
is off; verified memory decoding is enabled after BAR restoration. The
device-typed BAR0 covers registers through `0xd387`.
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
- `Ath9k::baseband` reports `BasebandPrepared`: the 2412 MHz reference
  frequency, selected EEPROM high-power gain/SYNTH9 XE2 variant and count
  of programmed INI rows. Successful preparation also applies normalized
  EEPROM modal/RF board values. It records inactive register preparation, not
  channel authorization or a calibrated/operational PHY.
- Errors distinguish absent/mismatched silicon, timeout, invalid EEPROM
  magic/length/checksum/version, and invalid factory identity.

The former reset-only `Ath9k::new` constructor is removed. Construction
goes through the PCI authority and identification path. Successful probe
records hardware identity and then programs Linux's AR9285 2GHz HT20
mode/gain/common tables (655 writes), ordered PLL/analog shift setup and RF
synth reference registers with bounded responsive settling delays. All
four gain-table combinations use the actual factory TXGAIN and SYNTH9
selection. It does not register a netdev or imply a WLAN.
The modal stage programs switch controls, IQ coefficients, RX attenuation
and margins, EEPROM antenna-diversity controls, versioned OB/DB analog
fields, settling/ADC/XPA/RX timing, CCA thresholds and baseband power scale.
Analog updates use bounded settling delays. Dynamic diversity combining
is not enabled by the current reference-channel probe.

Native register reads and writes validate complete aligned BAR extents and
execute inside `Cap::invoke`; revoked reads return all ones, revoked writes
are refused, and preparation cannot report success after authority loss.

## 4. Invariants

- PCI parking is verified by command-register readback before BAR sizing: BME
  and memory decode off and INTx masked. Decode is enabled only after sizing
  writes are restored; MMIO follows that readback. Additional
  matched singleton radios are parked with BME/memory decode off and rejected.
  Repeated dispatch of the owned address fails before parking.
- BME remains disabled throughout identification and baseband preparation.
  PHY activation, MAC RX, all ten TX queues and interrupts remain disabled;
  no unowned DMA rings can run. The common table's cleared DIAG_SW is
  followed by restored RX_ABORT/RX_DIS before any PHY activation.
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

Stage 5 identification/baseband prerequisites. Traced smokes exercise the live
identification helper, complete EEPROM extent, reset register order,
endianness/checksum/version validation and invalid/busy hardware cases.
Independent hashes from Linux cover every address/value pair for all four
production INI choices; fixtures also verify PLL/RF values, analog delays,
BAR bounds and that packet/PHY engines stay disabled.
Complete modal/RF write traces match independently compiled local Linux
`eeprom_4k.c` functions and register/EEPROM definitions for four EEPROM,
modal-version, HT40 and diversity cases. Native MMIO tests revoke an actual
object-table epoch before deliberately invalid BAR addresses, proving no
post-revocation read/write occurs.
They do not prove RF or packet operation.

## 8. Remaining software and physical acceptance

Software still required before AR9285 is ready for physical Wi-Fi testing:

1. Complete the partially prepared PHY: channel-mode overrides, chain
   masks and delta slope/spur handling, power/antenna policy, CTL/PDADC
   application, noise-floor/IQ/PA calibration and regulatory limits.
   The fixed inactive reference synth setting does not implement channel
   switching or radio activation. PCIe power-save/PM setup also remains.
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
