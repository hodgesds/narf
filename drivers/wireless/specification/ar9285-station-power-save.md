# AR9285 source-qualified station NETWORK_SLEEP

The admitted AR9285 revision2 HT20/full20/40 station program implements the
existing wireless power-save frontend, PM signalling, manual TIM/DTIM wake,
PS-Poll buffering and actual NETWORK_SLEEP/awake transitions. It requires a
new externally measured and signed **N85S1** program. No board measurements,
signed deployment asset, over-air interoperability, power savings or latency
result is supplied. Eight native cases are written and await execution.

## Public setting and retained operation

`Ath9k::power_save_qualification_request()` returns factual source identity,
MAC and filename. It grants neither RF emission nor sleep. The existing
`WirelessNetIface::{power_save_default,set_power_save}` methods expose the
**desired** setting through the real nl80211 SET/GET power-save boundary.
Absent valid N85S returns unsupported; the default remains awake. A successful
SET retains intent in the Radio owner. It does not claim that a PM notice,
its native ACK or a hardware transition has completed.

The owner waits for actual association, controlled port, installed PHY and
optional BA/QoS source ownership. A fresh current BSSID beacon with a valid
unique TIM and actual association AID supplies the timer program. A genuine
PM1 Null goes through the actual Packet descriptor/DMA/doorbell path. Only
its exact successful native TX receipt, idle QCU and fresh RX-idle fence
commit the AP notice. PM0 uses the same path before awake mode is restored.
Changing the setting or returning from SET cannot discard an already
published notice. Completed PM0 retires TIM facts; re-enabling needs a fresh
beacon and newly programmed timers. Cold retune, disconnect, suspend, key/
peer failure and generation retirement retain the original terminal fences;
no association preservation across cold reset is inferred.

## N85S1 record and measurement obligation

The filename is `ath9k/ar9285-sta-ps-v1-ch<P>-ext<S>-<MAC>.bin`, where S is
zero for20 and the actual secondary channel for40. Firmware loader signature
verification and current firmware capability invocation are mandatory. The
body is exactly128 bytes with little-endian scalar encoding:

| Bytes | Meaning |
| --- | --- |
| 0–7 | `N85S`, version1 and header length128 |
| 8–11 | total length128 |
| 12–15 | PCI168c:002b |
| 16–47 | exact source request identity |
| 48–53 | actual factory MAC |
| 54–57 | exact current H geometry body |
| 58–59 | maximum installed antenna gain, signed half-dBi,0..128 |
| 60–61 | measured complete-program conducted peak, signed half-dBm |
| 62–63 | qualification ceiling, signed half-dBm |
| 64–65 | minimum beacon interval1 TU |
| 66–67 | maximum beacon interval1024 TU |
| 68 | maximum DTIM period255 |
| 69 | at most8 PS-Polls per fresh TIM beacon |
| 70–71 | actual wake/RX-abort proof bound2000 microseconds |
| 72–73 | maximum PS-Poll data wait1024 TU |
| 74 | exact current H version1/2/3 |
| 75 | single chain1 |
| 76–79 | zero |
| 80–111 | SHA256 of the complete accepted current H body |
| 112–127 | zero |

Every fixed bound is exact; arbitrary versions, widened limits, reserved
bytes, foreign identity/geometry/body and unsigned records fail closed.
Peak/ceiling ranges are -512..256 half-dBm. Antenna bound cannot be below the
current H antenna bound. Peak plus antenna must fit the S ceiling, base H
ceiling and every currently overlapping host rule over the full occupied
20/40 span. Current base and S capabilities enclose actual operations.

The identity hashes the exact raw factory/base calibration/H body and
geometry, single-chain host-CCMP modes, complete control/timer/IRQ/clock
program and the independent RX-BA, legacy sender-BA, larger sender-BA and
QoS source request identities. Old H/B/T/Q formats and identity recipes are
unchanged. Their own current grants remain independently necessary when
those programs are active; S never creates an agreement or widens their
bounds. The S measurement is global over the complete optional composition,
including all1..8-MPDU/64-BAW/three-retry/four-AC/eight-TID programs, automatic
responses, PM Null, PS-Poll, PM-marked DATA/EAPOL, RX abort and clock/timer/IRQ
transients, at every supported temperature/supply/antenna/BT/posture point.
A nominal-temperature number or static packet measurement cannot qualify
this program. No runtime gain, antenna switching or periodic calibration is
authorized. Missing S leaves all existing awake behavior unchanged.

## Actual source control and key ownership

Pinned Linux `net/mac80211/mlme.c::{ieee80211_send_pspoll,
ieee80211_send_nullfunc}` sets DONT_ENCRYPT for these controls. This program
uses its valid non-QoS24-byte Null branch: ToDS, actual own/AP addresses,
PM1/PM0 and normal non-QoS sequence ownership. WPA2 reserves its sequence via
shared `Security::reserve_plain_control_sequence`; Open uses the driver
counter. It consumes no CCMP PN and installs no hardware key. The control is
source-admitted separately rather than widening shared DATA crypto.

PS-Poll is the actual16-byte Control frame with AID|0xc000 in Duration,
current own/AP identity and PM1. AR9002 FrameType is2 and DurUpdate is clear,
matching `xmit.c::get_hw_packet_type`, `ath_tx_fill_desc` and
`ar9002_mac.c::ar9002_set_txdesc`. The ordinary descriptor validators retain
their existing frame restrictions. Only the private S encoder admits this
short control. A PS-Poll ACK alone does not invent buffered DATA: a current
unfragmented authenticated unicast response, or the source-valid plaintext
AP Null response, completes the wait. MoreData drives another poll, bounded
to8 per fresh beacon. DTIM CAB holds awake until current group data clears
MoreData or a later current beacon retires the missing CAB indication.

Ordinary DATA and protected EAPOL retain their original shared encryption,
PN/sequence, replay and native receipt owners. Only the mutable PM header
bit is set after crypto while the AP PM state is active; CCMP AAD excludes
PM. Descriptor admission uses a separately unmarked copy under current S,
while DMA, retry and native receipt comparisons retain the actual PM-marked
original. Security replies separately retain the shared exact unmarked
original for the shared pending-reply commit. Key replacement cannot commit
an old receipt or discard ambiguous published DMA. PS/BA/rekey/copy work and
a receive-budget exhaustion prevent sleep. Recipient-BA replies observed
behind a completed PM TX are retained in a bounded eight-entry unpublished
control queue while key/peer RX updates drain. Epoch retirement clears that
queue. Only current-source native publication after the real PS receipt may
send a reply; its BA ticket still activates only after its own exact native
ACK/idle receipt. Queued controls prevent DATA and sleep admission.

## Hardware timers, IRQ, awake access and terminal proof

AR9285 has no AUTOSLEEP. The source program follows
`common-beacon.c::ath9k_cmn_beacon_config_sta` and
`hw.c::ath9k_hw_set_sta_beacon_timers`: actual stable hardware TSF64, source
2+6-TU next-TBTT adjustment, beacon/DTIM alignment,100ms sleep roundup capped
at DTIM,3-TU early wake, CAB timeout80, non-AUTOSLEEP beacon timeout1,
BMISS threshold10 and TSFOOR0x4240. Beacon intervals1..1024TU and valid DTIM
count/period are parsed from the actual current beacon. Native timer writes,
RSSI threshold, TIMER_MODE and IRQ masks all require readback.

The source enables real TIM_TIMER plus BMISS/TSFOOR causes. Installed MSI
uses the existing vector/bottom half; without MSI the existing1ms scheduled
poll services actual cause registers while PCI INTx remains disabled. No
unregistered INTx route is enabled. TIM wake actually clears RX_ABORT/RX_DIS
before waiting for the current beacon; TSF out-of-range requires a fresh
beacon resynchronization. BMISS fails the peer. IRQ kill/service/rearm and
all normal packet/current-policy/readback checks remain in force.

Only a quiet retained owner with no control/key/BA/TX/copy/RX work may
attempt sleep. Actual all-ten-QCU idle, QTXE clear, IER/timer/wake cause and
RX-state0 proofs precede STA_ID1.PWR_SAV and FORCE_WAKE_ON_INT. Actual RTC
SLEEP4 is required within2ms. Every published ring/buffer remains mapped.

Before every later native MMIO, descriptor, payload or copy operation,
fresh base/S and PCI invocations enclose the actual access. Raw RTC access
is deliberately below the ordinary access adapter, avoiding recursive wake
checks. Actual sleeping wake uses FORCE_WAKE_EN,50us settle and actual
RTC_ON2 within2ms, then clears STA_ID1.PWR_SAV. It rejects SHUTDOWN1 because
restoration would require full PLL/reset and generation/key/DMA retirement.
Running awake accesses also prove actual RTC_ON2. Source/host/RF-silent or
readback loss, ignored transition writes, timeout or bad PM receipt closes
the owner. BME-off still uses its independent current PCI authority; only
existing complete terminal DMA proof releases mappings. Ambiguous clock,
source or stop state quarantines them.

The model fixtures exercise actual production control/descriptor/timer/
IRQ/Packet/Radio/Device and Narf-Ring/kernel network paths with synthetic
signed inputs. They include Open/WPA2, held ACK/live QCU, true hardware
sleep/ignored wake/shutdown, public desired-policy reversal and re-enable,
TIM/MoreData/empty Null/CAB, actual current GTK delivery, eight original
PN/sequence/PM frames and real Group2 receipt, and fresh20/40 calibration
with both extensions. They are written, not executed. Hardware acceptance
requires externally supplied measured assets and a physical radio.
