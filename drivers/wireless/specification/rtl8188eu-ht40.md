# RTL8188EU signed HT20/40 full-program qualification

This contract is part of [rtl8xxxu §3](rtl8xxxu.md#3-public-interface).
Implementation and eight native regressions are present; coordinated release
compilation and native execution are pending. No real board measurements,
signed deployment artifact or physical radio acceptance are supplied.

`firmware_transport::Owner::ht40_request(primary, secondary)` returns the
exact optional filename and recipe binding using the current executable and
primary N8PC qualification. It performs no radio I/O and grants no HT mode.
Legal primaries and secondaries are channels1–13 separated by four channel
numbers. The RF center is their midpoint, two channel numbers from primary.
The filename is `rtl8xxxu/rtl8188eu-ht40-lgi-v2-<12 lowercase MAC hex digits>-p<primary>-s<secondary>.bin`.
The registry verifies the signature; nonempty trusted signer metadata is
required even when development firmware loading permits unsigned images.
Missing optional assets preserve the old legacy/v1 path; invalid present
assets fail pure preflight before singleton/receive ownership is acquired.
The unchanged N8HT v1 parser, filename, binding and channel1 HT20 behavior
remain available. A v2 record binds the v1 recipe, not a separate measured
v1 artifact; its own measurements must qualify both20 and40MHz states.

The N8HT v2 payload is exactly1472 bytes. Integers are little endian.

| Byte range | Required value |
|---|---|
| 0..4 | magic `N8HT` |
| 4..6 | version:u16 = 2 |
| 6..8 | header bytes:u16 = 192 |
| 8..12 | total bytes:u32 = 1472 |
| 12..16 | exact USB VID:u16 and PID:u16 |
| 16..48 | full20/40 recipe SHA256 returned by the request |
| 48..77 | exact canonical29-byte factory identity from N8PC |
| 77..80 | zero |
| 80..112 | preceding N8PC payload SHA256 |
| 112..118 | repeated factory MAC |
| 118..124 | primary:u8, width40:u8, streams1:u8, LGI0:u8, secondary:u8, center:u8 |
| 124..126 | maximum antenna gain:i16, quarter-dBi |
| 126..128 | qualified EIRP ceiling:i16, quarter-dBm |
| 128..160 | unchanged N8HT v1 program recipe SHA256 |
| 160..192 | zero |
| 192..1472 | ten rows of64 conducted-peak upper bounds:i16, quarter-dBm |

Rows0 and1 qualify all CCK and OFDM rates respectively. Rows2–9 qualify
MCS0–7 separately. Every raw gain0–63 is either explicitly bounded in
-512..256 quarter-dBm or unknown (`i16::MAX`); unknown values grant nothing.
No interpolation, gain-index-to-dBm conversion or monotonicity assumption
is permitted. The antenna bound must be at least the N8PC bound and at
most128 quarter-dBi; the record ceiling is -512..80 quarter-dBm.

Each bound must cover the complete actual20MHz fallback AND40MHz LGI
program states, all selected legacy/autonomous responses, antenna, static
full LC/IQK, supported supply/manufacturing range and thermal0..63 envelope
with power tracking disabled. A point measurement at room temperature is
insufficient. V2 preserves the exact CCK/OFDM gain pair selected by the
current N8PC permission. Those gains must fit both the original N8PC
operating envelope and the new v2 full-program CCK/OFDM rows. Each MCS uses
a known index no higher than the actual PRIMARY factory HT40 base. Linux
`rtl8xxxu_config` passes primary to `rtl8188f_set_tx_power`; RF programming
subsequently changes the RF channel to CENTER. EU efuse initializes no
FU/EE per-rate difference: zero differences apply. A center-channel group,
foreign chip nibble or assumed conversion cannot raise that maximum.

The full occupied40MHz interval is center frequency minus/plus20MHz.
Every overlapping authenticated host rule must cover that entire interval,
permit at least40MHz and carry no unsupported restriction. The most
restrictive EIRP ceiling is intersected with the primary N8PC permission
and signed v2 ceiling. This full-profile policy applies even when the v2
native owner selects its20MHz fallback; it does not enlarge v1 rights.
All current executable, N8PC and v2 artifact capabilities and policy facts
are rechecked around each asynchronous poll and native packet publication.
No artifact, selected gain array or peer IE alone proves native programming.

The sealed native program is created only while MAC TX/RX are parked,
after actual BB/RF/gain/SIFS writes and exact readbacks. It binds the selected
geometry,20/40 mode, measured gain snapshot and current sources. Forty uses
`BWOPMODE0x603.2=0`, `FPGA0x800/0x900.0=1`, primary-specific `RRSR0x440.21/22`,
`CCK0xa00.4`, `OFDM0xd00.10/11`, `FPGA0x818.26/27`, and RF0x18 center with
BW0x400. Twenty uses primary and BW0xc00. Legacy gain registers and MCS
`0xe10/e14` are read back; OFDM SIFS is16us and CCK SIFS is preserved.
A native transition, even on the same primary, must retire old RXDMA,
actual USB receipts and MAC/FIFO contents through the existing cold restart.
Cancellation/error never proves old EP0 or packet DMA can be reused.

Only a matching signed/current secondary is offered to the selected peer.
Complete shared HT capability/operation/WMM negotiation binds the response
to that offer. An AP response may narrow40 to20; the same logical peer is
retained while a real cold20 restore completes before keys or data open.
Scans and administrative wake restore the exact saved native mode/geometry;
away scan receivers retain their NOHT profile. The implemented SISO subset
is MCS0–7/LGI with the existing whole3839-byte A-MSDU/BA/software-CCMP path;
MCS32, SGI,2SS, VHT and additional emissions are not advertised.

Native QoS DATA and QoS Null use source TXDESC32/v3 BW bit25 and primary
position bit20/21, retaining host sequence/rate/fallback/BA rules and checked
checksum. Management stays on the existing basic1Mbps path. RXDESC16 BW40
requires a private seal installed by the actual native receiver after its
stream cut; a caller-set descriptor bit cannot mint that proof. Both widths
retain LGI/fragment/aggregation/crypto checks. This old PHY block reports
SGI/RXSC but no independent channel; like Linux, v2 uses the actual native
geometry rather than interpreting RXSC as a channel. Current-source/policy
failure permanently retires that native program and its copied seals.
A later installation has its own validity state.

Eight native registrations under `drivers/wireless/rtl8xxxu/ht40` exercise
full-program identity and primary factory maxima, literal plus/minus BB/RF
and DATA descriptors, Open/WPA2 DHCP/CCMP, initial and response-narrowed20
fallback, actual same-primary stream retirement, parked wake, current
secondary-span restrictions, actual held DATA/EP0 source loss, BA/replay
continuity and associated active restore. Physical USB, RF and AP inputs
remain inert; these tests cannot supply measurement or hardware acceptance.
