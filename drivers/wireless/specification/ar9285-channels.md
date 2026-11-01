# AR9285 exact-channel generations and N85H/B/T/Q v2

This is an externally supplied measurement contract. The implementation
supplies no physical measurements, signed asset or board acceptance. Its
source-complete channel1–13 continuation and six new native cases are pending
release/native validation.

The admitted program is the retained AR9285 revision2 one-chain
`eeprom_4k` owner, full-rate20, legacy CCK/OFDM and optional HT20 MCS0–7 long
GI, RX STBC1, recipient BA, bounded two-MPDU sender BA and four-AC/eight-TID
scheduling. AR2427 shares only the legacy program. Channel14/2484MHz Japan
CCK-only, HT40/SGI40, tracking and other chips are not admitted by these
records.

A target channel is1–13 and frequency is2407+5*channel MHz. The complete
occupied span is frequency−10 to frequency+10 MHz. Every overlapping current
host rule constrains power and must permit20MHz without DFS, indoor-only or
NO_IR assumptions; at least one rule covers the full span. Current country
must match the actual calibration report, and the current ceiling must still
cover the installed program. Factory target/CTL interpolation and antenna
gain reduction precede PHY activation; a new channel whose budget is below
its factory antenna gain is refused before retirement. Metadata alone never
substitutes for that channel's completed PA/leakage/NF/IQ receipt.

The existing channel1 v1 records are unchanged byte for byte, including their
request hash recipes and filenames. Version2 is accepted only for channels2–13.
The new N85H request prefix explicitly binds the selected MHz and complete
cold-reset/INI/synth/slope/spur/detector/CTL/current-host-calibration program,
then retains all preceding identity/EEPROM/gain/report/power/native ownership
and static-envelope facts. A foreign channel, report, prepared frequency,
EEPROM, target-power array or calibration result produces another request.
N85B/T/Q v2 requests additionally bind the exact base N85H identity and entire
signed payload digest. A v1 asset never authorizes another channel.

| Record | Version2 filename under `ath9k/` | Length | Fields at offsets54–57 |
| --- | --- | ---: | --- |
| N85H | `ar9285-ht20-v2-ch<C>-<MAC>.bin` |160| primaryC / width20 / chain1 / GI0 |
| N85B | `ar9285-rxba-v2-ch<C>-<MAC>.bin` |96| primaryC / width20 / chain1 / program1 |
| N85T | `ar9285-txba-v2-ch<C>-<MAC>.bin` |96| primaryC / width20 / chain1 / program2 |
| N85Q | `ar9285-qos-v2-ch<C>-<MAC>.bin` |96| primaryC / width20 / chain1 / ACcount4 |

All integer fields are little endian, MAC is twelve lowercase hex digits and
C is decimal. Common headers retain magic at0, version:u16=2 at4,
header:u16=length at6, length:u32 at8, vendor0x168c/device0x002b at12,
request SHA-256 at16 and exact MAC at48. Every other field, reserved-zero
requirement, measured peak dimension, antenna/ceiling unit, source nesting,
BA/window/TID geometry, static envelope and native response/transient
obligation remains the corresponding v1 definition in `ath9k.md` §§3.1–3.4.
Only the named channel is authorized. There is no interpolation of measured
qualification across channels and no inferred temperature/supply/antenna/BT
or posture envelope.

Current grants, current PCI capability and current channel permission enclose
actual descriptor/payload/capture access and final publication. For the new
per-channel native program, the same PCI invocation also loads actual
AR_PHY_SYNTH_CONTROL, AR_PHY_TURBO and all seven installed factory-limited
rate-power registers. Preparation reads back frequency-dependent stable
channel/detector/rate writes; modal analog writes keep their real source
settling sequence. Source loss, policy loss or readback failure supplies no
permission to reuse another report or silently rewrite lower power under an
old qualification.

A cold transition owns and completes physical retirement independently of its
public waiter. It withdraws the old interface, clears software queues and
capture, fails keys, retires both BA directions and proves all TX/RX DMA
quiescent. Only then does it reset the same function, re-read identical
factory identity and image, and create a newly calibrated station. Old names
stay reserved; the successor has a fresh name and fresh closed/publication
and receive-epoch tokens. Association is lost. The caller must discover the
new interface; successful multi-channel scan restores the original RF
primary with another fresh generation, not the old objects. Failed or
cancelled scans promise terminal ownership, not restoration.

The Linux7.2 implementation chain is `main.c::ath9k_config` →
`channel.c::ath_chanctx_set_channel` → `channel.c::ath_set_channel` /
`ath_reset_internal` → `hw.c::ath9k_hw_reset`. The selected channel reaches
`ar5008_phy.c::ar5008_hw_process_ini`,
`ar9002_phy.c::ar9002_hw_set_channel`/`ar9002_hw_spur_mitigate`,
`eeprom_4k.c::ath9k_hw_4k_set_txpower` and `ar9002_calib.c` initial
calibration. NARF deliberately uses the full reset path, not fastcc or a
replayed one-shot calibration. Linux's channel14 Japan CCK-control bit is a
separate unadvertised profile. Exact local source hashes and function lines
are preserved in `target/wifi-validation-evidence/ath9k-channel-source-pins.json`.
