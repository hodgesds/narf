# AR9285 periodic calibration and ANI (N85P1)

## 1. Purpose and scope

N85P1 authorizes the admitted AR9285 station's complete live calibration
program at its actual full-rate20 or exact40 geometry. It adds the source
ADC/IQ, PA, noise-floor and ANI continuations to an unchanged current H1/H2/H3
owner. No signed production asset or physical measurement is supplied.

The software and six native composition cases are written. Release/native
execution and physical acceptance are pending. Existing H/B/T/Q/S formats
retain their bytes and behavior when P is absent.

## 2. Source and physical assumptions

The pinned Linux7.2 `ath9k/link.c::ath_ani_calibrate`,
`ar9002_calib.c::{ar9002_hw_calibrate,ar9285_hw_pa_cal}`,
`calib.c::{ath9k_hw_getnf,ath9k_hw_loadnf,ath9k_hw_start_nfcal}`,
`ani.c`, `ar5008_phy.c::ar5008_hw_ani_control_new`, common `ath/hw.c`
cycle-counter code and `common.c` beacon RSSI filter define the program.
AR9285 has no MRC-CCK hardware. Its ANI uses the old OFDM500/200 and
CCK200/100 errors-per-second thresholds, with a300ms listen window and
1000ms monitor period.

An external qualification must bound the complete program across the actual
raw factory image, initial calibration, occupied span, per-rate power plan,
temperature0–63, supply, antenna, BT and posture envelope. It covers all
source PA offsets0–127, enabled IQ/ADC coefficients, ANI levels, intermediate
calibration/load/restoration states, automatic responses, retries and every
admitted B/T/Q combination through eight original MPDUs. A nominal H peak
does not imply this qualification.

P1 requires actual RTC_ON2 and excludes S1 NETWORK_SLEEP. Existing suspend
retires the whole generation. A separately measured successor is needed to
combine live tracking with station doze; P1 grants no live wake authority.

## 3. Request and signed record

`Ath9k::periodic_calibration_request()` returns identity, MAC and filename
metadata from the current retained H owner. Provision the matching optional
asset before association. A missing/invalid P source leaves the static
program; a bound source losing authority closes the generation. A later
association may discover a newly provisioned source.

The registered firmware loader verifies the signer. The body is exactly160
bytes, little-endian scalar fields, with no trailing data:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | `N85P`, version1, zero, length160LE |
| 8 | 4 | Exact body length160 |
| 12 | 4 | PCI168c:002b |
| 16 | 32 | Complete request identity |
| 48 | 6 | Original factory MAC |
| 54 | 4 | Exact H geometry body |
| 58 | 2 | Signed antenna upper bound, half-dBi, at least H's bound |
| 60 | 2 | Signed global conducted upper bound, half-dBm |
| 62 | 2 | Signed full-program EIRP ceiling, half-dBm |
| 64 | 4 | Short interval1000ms |
| 68 | 4 | Long interval30000ms |
| 72 | 4 | Reset-valid interval1200000ms (20min) |
| 76 | 4 | ANI interval1000ms |
| 80 | 4 | Single-calibration timeout30000000µs |
| 84 | 4 | NF measurement/load timeout222000µs |
| 88 | 4 | Original H version, chain1, zero, zero (no S1) |
| 92 | 32 | Complete original H body digest |
| 124 | 4 | Log-count10, one sample,64 temperature points,128 PA offsets |
| 128 | 32 | All zero |

The request also hashes H identity/digest/MAC/version/geometry and the exact
independent B/T/T4/Q request identities plus the full program semantics.
Unknown versions, unsigned/revoked/foreign sources, dimensions, intervals or
reserved values fail closed. Current global peak plus antenna must fit the
P ceiling, original H ceiling, **each actually installed child's signed
ceiling** and every overlapping current host rule over the complete span.
All installed child capabilities remain independently current around actual
I/O and publication.

## 4. Live receipts and ownership

The initial H Report/WideReport and signed digest never change. A separate
native live receipt records actual enabled IQ/ADC, PA offset, filtered NF,
CCA configuration and masked ANI fields. Every ordinary native MMIO, DMA
payload/descriptor and copied-frame admission retains current P/base/PCI
authority and actual live readback. Geometry, center, power plan, one-chain
mode, RF-silent, RTC and BME checks remain current; P replaces only the
calibration fields.

Actual measurement starts at log10, one sample. HT40 runs ADCgain, ADCdc,
then IQ;20 runs IQ only. Actual DO_CAL busy and completion edges precede
source arithmetic and readback. While hardware measures, ordinary traffic
uses the exact prior coefficients and bounded mode. At30s, the retained
worker clears only the exact old DO_CAL operation under actual quiet, keeps
all old ticket mappings/coefficients and mints no fresh measurement. It runs
before ordinary access would reject the expired receipt.
An enqueue-first request at that deadline returns temporary no-admission
without MMIO, DMA publication or PN/SC reservation. The retained bounded
poll worker performs the actual source-qualified quiet retry.

Fresh host coefficient/PA/ANI writes wait for all original native and
software DATA/control/security continuations and genuine RX idle. The same
owner proves all ten QCUs/TXE idle, asserts RXabort and observes RX state0
within2ms. It publishes mutation denial before changing registers and retains
the same RX/TX allocations, keys, PN, SC, BA, peer and capture epoch. A
completed live receipt and actual RX-unabort readback precede normal polling.

The NF median-load continuation stays inside the scheduler's bounded
responsive polling primitive; no healthy partial mutation escapes Radio
poll. Every poll retains the original token and deadline. No private
iteration-count wait or invented hardware completion is used.

## 5. Algorithms and state

Short work runs each second until its actual list completes; validity resets
after20min. Long PA/NF work runs every30s, or1s on actual NF interference.
High-power factory TXGAIN skips PA. The normal branch runs the actual analog
comparator program, restores all saved registers and proves the new7-bit
offset. Unchanged offsets back off to at most eight skipped long rounds;
a skip retains the prior factual offset.

NF uses actual signed9-bit control and, for40, extension readings, source
sanitization and five-entry history (first five observations, then median).
The actual hardware median-load busy/completion edge precedes maxCCA=-50
restoration. A stuck load never restores that value or claims a fresh receipt.

ANI freezes/reads/clears actual MIB cycle counters, uses44/88MHz listen
arithmetic, and reads actual OFDM/CCK timing counters. Current-peer native
beacons supply source fixed-point RSSI. Source OFDM/CCK turns change the seven
masked sensitivity registers and read back. Initial INI values are retained
until an actual level transition: the logical default spur level3 is not a
request to replace the actual INI with the transition formula. Peer/key
epochs withdraw old pending ANI/RSSI decisions and restart its counters;
they do not reset keys or pretend to refresh hardware calibration.

## 6. Terminal and composition rules

P1 and S1 binding are mutually exclusive. On a P owner the real power-save
trait reports unsupported; SET returns EOPNOTSUPP without killing the station.
Installing P never silently widens the accepted S1 measurement contract.

Source/PCI/policy/RTC/geometry/power loss, ignored writes, clock reversal,
ambiguous completion or NF timeout denies CPU admission. The independent
existing terminal owner still attempts BME-off. DMA is released only by the
complete original stop proof; otherwise all mappings stay quarantined.
Repairing a register or relaxing policy cannot reopen that generation.
Cold retuning creates a fresh physical owner and retains its existing
association/key/BA/capture loss rules.

## 7. Native cases and validation

Six unexecuted native cases use actual Device/Radio/Packet/DMA/IPC paths.
They cover source shape/current authority and absent-P preservation; Open/
WPA2 traffic during measurement, actual IQ completion and kernel DHCP;
actual ANI counters, PA/NF/load and20min restart; held original/QCU, timeout,
revocation and ignored writes; full reset/EEPROM/fresh40 on both extensions
with ADCgain/DC/IQ and eight actual originals; and BE high-power factory,
stuck median load and an independently stricter installed child ceiling.
Fixture assets and register inputs authorize isolated models only.

## 8. Remaining physical acceptance

No production board measurement, temperature/supply sweep, RF qualification
or physical AP result is claimed. Those inputs must supply the matching
signed complete-program record. Release/native results remain pending;
the source implementation does not replace physical qualification.
