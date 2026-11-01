# RTL8188EE signed automatic antenna full-program qualification

This is part of [rtlwifi §3](rtlwifi.md#3-public-interface). NEAN v1 and six
composed native cases are implemented pending coordinated release compilation
and final native validation. No antenna measurements, thermal curves, signed
board deployment assets or physical RF acceptance are supplied. Existing
NEPC, NEHT, NERT and NETH payload formats and recipe hashes are unchanged.

NEAN is an optional extension for actual factory EFUSE0xc9 types1
(CG_TRX_HW_ANTDIV),2 (CGCS_RX_HW_ANTDIV) and4 (CG_TRX_SMART_ANTDIV).
Fixed/unknown/erased types retain the preceding static program. The exact
factory map, executable, NEPC, measured NEHT, measured NERT and measured NETH
payloads identify the program; no shared firmware signature, default antenna
type or prior static measurement authorizes another physical path. Type1/2
use native hardware diversity and type4 uses native SMART training.

`RtlwifiDevice::antenna_diversity_request()` returns the actual selected
program's filename and binding without radio I/O. Provision optional NERT
and NETH records first when the desired program uses protection or thermal
tracking. The filename is
`rtlwifi/rtl8188ee-antenna-v1-<12 lowercase MAC hex digits>-p<primary>-s<secondary>-h<profile>-r<protection>-t<thermal>-a<factory-type>.bin`.
Secondary is0 for20MHz; profile is0 for legacy,2/3 for measured HT20 or4
for the full measured HT20/40 program. Protection and thermal are0/1 flags.
V4 always retains the full40MHz policy span even during actual20 fallback.
The registry verifies signatures and the parser requires nonempty trusted
signer metadata. No development unsigned policy substitutes for this record.

The NEAN v1 payload is164160 bytes, with little-endian integers:

| Byte range | Value |
|---|---|
|0..4 | magic `NEAN` |
|4..6 | version:u16 =1 |
|6..8 | header bytes:u16 =320 |
|8..12 | total bytes:u32 =164160 |
|12..16 | PCI VID0x10ec, DID0x8179 |
|16..48 | exact NEAN recipe SHA256 |
|48..80 | canonical exact factory SHA256 |
|80..112 | exact NEPC payload SHA256 |
|112..118 | repeated factory MAC |
|118..124 | primary, full-profile width20/40, streams1, factory antenna type1/2/4, secondary-or0, center |
|124..126 | maximum antenna gain for hardware selector0:i16, quarter-dBi |
|126..128 | maximum antenna gain for hardware selector1:i16, quarter-dBi |
|128..130 | artifact EIRP ceiling:i16, quarter-dBm |
|130..136 | dimensions2 selectors,64 temperatures,10 rate families,64 gains, reserved0/0 |
|136..168 | exact measured NEHT payload SHA256, or zero |
|168..200 | exact measured NERT payload SHA256, or zero |
|200..232 | exact measured NETH payload SHA256, or zero |
|232..320 | all zero |
|320..164160 | selector0 then selector1, each64 thermal planes x10 rows x64 signed:i16 conducted peaks |

Each antenna bound is at least every preceding bound and at most32dBi.
The ceiling is−128..20dBm; known conducted peaks are−128..64dBm.
`i16::MAX` means unknown. Thermal order is raw0–63; rows are CCK, OFDM,
MCS0–7; gains are0–63. Each selected gain needs a known bound in every
thermal plane on both possible hardware selectors. The parser retains
2560 bytes of maxima, rather than a164KiB stack object. Unknown bounds
never interpolate, inherit from another antenna or become legal because
that path has not yet been observed. All preceding factory/gain/curve,
antenna, full-span and current host-policy limits still apply. Neither an
antenna request nor an RX power sample grants RF authority.

The hardware selector labels refer to the actual programmed mux codes,
not guessed left/right board wiring. Measurements must cover the exact
source mapping0x914=0x0201 and factory-type program, both possible physical
paths, autonomous switching between them, static-to-dynamic initialization
and return, every training and thermal/gain transition, all valid IQK/LCK
results and tones, all ordinary/autonomous/control/retry emissions, supply
and full thermal/sampling-lag range, and preceding awake/leisure/IPS/recovery
behavior. Measurements must cover both widths and20 fallback under v4,
LGI/SGI20, QoS/BA and optional RTS/CTS/NETH. DATA-only or room-temperature
peaks are insufficient. Old NEFB does not qualify this composition and stays
excluded while NEAN is installed.

The source is pinned Linux7.2 `rtl8188ee/{hw,phy,dm,trx}.c` and `trx.h`.
Initialization programs/readbacks MAC antenna pins0x4c[23,25], pin mux
0x870[8:9], RX control0x864[10], LNA0xb2c[22,31], OFDM0xca4, CCK
0xa74[7]/0xa0c[4], mapping0x914 and type-specific TX/RX controls. Type1
uses MAIN selector1/AUX0; type2 uses MAIN0/AUX1. The first default write is
forced and read back. The implementation deliberately uses the factory type
for these codes: pinned `dm.c::rtl88e_dm_update_rx_idle_ant` compares the
prior logical idle antenna to a diversity-type constant, and can also skip
initial programming when a logical default already matches. That alias is
not copied. The exact corrected program is in the signed NEAN recipe;
physical mapping still requires external board qualification.

Actual RX PHY byte27 bits7,6,0 produce the mux. Complete native MPDUs carry
that mux and the existing actual PHY-derived PWDB through DMA copying.
Only AP-bound station traffic contributes to the hardware-diversity average;
SMART additionally requires a native frame directed to the station while
training. Missing PHY, foreign BSSID and selectors outside the configured
pair supply no antenna sample. A2s watchdog compares per-selector averages,
keeps the current selector on ties, resets counts and updates actual RX
idle/default/optional controls. Type1 also updates response/default TX
controls and the per-peer TX selector. Type2 retains the source RX-only
behavior and adds no per-descriptor TX override.

SMART uses the source's actual `ant_combination=2`: default0, optional1,
selector-count field1. Source scratch arrays have seven entries, but this
program configures two combinations; unconfigured codes cannot become a
third path, including zero-PWDB ties. Training writes the station's actual
MAC to0x7b0/0x7b4 and enables0xe08[16]/0xc50[7]. A real2s deadline separates
start and finish; actual native own-directed samples select the best known
configured mux. No samples keep the preceding TX selection and disable
training. Source selector0 completion clears IGI diversity. Type1/SMART
normal descriptors carry antenna A/B in DW2[24,25] and C in DW7[29]; existing
byte order, frame length, density, BA, width/SC/GI, RTS, software CCMP and
native OWN/linked-next fields remain independently owned. Command-beacon
descriptors retain the source command path.

Every selection/training transition waits for a real host TX receipt,
actual full SCH_TX_CMD idle, all-queue pause and ordinary MAC TX/RX closure.
Antenna masks, original gains, RF18 geometry and reopened gates are read back.
Native buffers, key/PN history, BA/reorder state and original OWN receipts
remain retained. A TX antenna choice changes no receive identity, so copied
tokens retain the same current full-program authority for both possible paths.
The actual firmware/NEPC/NEHT/NERT/NETH/NEAN capabilities enclose each native
poll, TX publication, live EDCA/timing update and copied IPC/stack callback.
NETH candidate gains are checked against both NEAN paths before programming
and before reopening. Unknown measurements, source loss, failed readbacks,
missing scheduler idle and cancelled RF waits fail closed.

The exact prior masked antenna program is saved. A subsequent peer selection
restores that static program and repeats real IQK/LCK on the original path
before withdrawing NEAN authority; an IQK result from another antenna cannot
be relabelled as a static-program receipt. Then ordinary current NETH gain
restoration and new peer width/qualification selection proceed. Disassociation
retains the owner and the source watchdog withdraws linked diversity/training;
recovery creates a fresh radio/calibration/measurement owner.

The pinned EE driver has no manual `set_antenna`/`get_antenna` callback.
This continuation implements automatic selection and does not advertise
manual nl80211 antenna masks. That absence is not replaced by an inert setter.

Six new `drivers/wireless/rtlwifi/antenna` cases use actual retained
Firmware/PacketIo/Prepared/Device, native PHY/descriptor/peer/security owners
and kernel DHCP: signed factory/payload identity and other-selector thermal
holes; type1/2/HP initialization and real PHY average/tie/negative samples;
SMART real deadline/own-target/no-sample/selection; HT40+RTS+NETH composition;
qualification/MMIO/scheduler/cancellation/static-restore failures; and source
revocation after real RX copy and during held M4 OWN. These cases are written
but unexecuted. Release compilation and final native/full-matrix acceptance,
external measurements/signing and physical antenna/RF/peer validation remain
required.
