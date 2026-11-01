# RTL8188EE signed HT20/40 full-program qualification

This contract is part of [rtlwifi §3](rtlwifi.md#3-public-interface).
NEHT v4 is implemented with eight native regressions; coordinated release
compilation and execution are pending. No physical board measurements,
signed deployment artifacts or silicon/RF acceptance are supplied.

`RtlwifiDevice::ht40_request(primary, secondary)` returns the optional
filename and exact recipe SHA256 from the current firmware and NEPC
factory/payload identities. It writes no radio register and grants no RF
permission. The filename is
`rtlwifi/rtl8188ee-ht40-v4-<12 lowercase MAC hex digits>-p<primary>-s<secondary>.bin`.
Both primary and secondary must be channels1–11 separated by four channel
numbers; center is their midpoint. Registry signature verification and
nonempty trusted signer metadata are required. Missing optional v4 assets
preserve the existing path. Invalid present data fails before first BME or
packet admission. Existing NEHT v1/v2/v3 meanings are not reinterpreted:
v2 is the accepted channel1 HT20/SGI20/7935RX program and v3 is its separately
qualified channel2–11 extension. V4 binds the appropriate v2/v3 recipe;
a separate measured v2/v3 payload is not a prerequisite for v4 measurements.

The NEHT v4 payload is exactly1472 bytes, little endian:

| Byte range | Value |
|---|---|
| 0..4 | magic `NEHT` |
| 4..6 | version:u16 = 4 |
| 6..8 | header bytes:u16 = 192 |
| 8..12 | total bytes:u32 = 1472 |
| 12..16 | PCI VID:u16 = 0x10ec, DID:u16 = 0x8179 |
| 16..48 | v4 full-program recipe SHA256 from the request |
| 48..80 | exact canonical factory SHA256, including the full efuse map |
| 80..112 | preceding NEPC payload SHA256 |
| 112..118 | repeated factory MAC |
| 118..124 | primary:u8, width40:u8, streams1:u8, profile1:u8, secondary:u8, center:u8 |
| 124..126 | maximum antenna gain:i16, quarter-dBi |
| 126..128 | qualified EIRP ceiling:i16, quarter-dBm |
| 128..160 | unchanged primary-channel v2/v3 program recipe SHA256 |
| 160..192 | zero |
| 192..1472 | ten rows of64 conducted-peak upper bounds:i16, quarter-dBm |

Profile1 is SISO MCS0–7, LGI40 plus the existing LGI/SGI20 fallback and
7935-byte receive promise. Rows0/1 bound all CCK/OFDM rates. Rows2–9 bound
each MCS separately. An index0–63 is explicitly bounded in -512..256
quarter-dBm or unknown (`i16::MAX`); unknown entries grant nothing. No
interpolation, monotonic raw-index assumption or index-to-dBm reporting
estimate substitutes for measured bounds. Antenna gain must be at least
the NEPC bound and no more than128 quarter-dBi; the ceiling is -512..80
quarter-dBm. Bounds must cover both complete20/40 native programs, static
factory antenna/full IQK/LCK, supported supply/manufacturing range,
thermal0..63, all legacy/autonomous/BA/control responses and transient
emissions with gain tracking disabled. A room-temperature point is
insufficient. No antenna/cable loss credit is inferred.

The primary and RF center have different factory lookup roles on EE.
Pinned Linux7.2 `rtlwifi/core.c::rtl_op_config` adjusts `wide_chan` by ±2,
assigns `rtlphy->current_channel`, then calls the chip's `switch_channel`.
`rtl8188ee/phy.c::_rtl88ee_phy_sw_chnl_step_by_step` passes that CENTER to
both `CMDID_SET_TXPOWER_LEVEL` and `RF_CHNLBW`. `handle_path_a` selects the
center's BW40 base without the HT20 signed nibble. Twenty fallback instead
uses PRIMARY plus the signed high nibble of efuse0x1b. Per-rate PG rows
follow the existing regulatory-mode logic. V4 caps each MCS gain to the
intersection of those two actual maxima, then selects only a known measured
peak fitting the current ceiling. The source path cannot be replaced by
RTL8xxxu EU's primary-only wide lookup.

The actual preceding NEPC primary-channel CCK/OFDM gain arrays remain
unchanged. Each index must fit its original NEPC envelope, the new v4
full20/40 CCK/OFDM peak row, and the CENTER factory/PG legacy maximum.
A stronger center-channel factory restriction rejects that profile instead
of silently increasing or substituting legacy gains. Native readback checks
the actual legacy arrays as well as both MCS dwords.

Current host policy must cover the entire occupied40MHz interval (center
frequency minus/plus20MHz). Every overlapping rule must cover that full
interval, allow40MHz and have no unsupported flags. Intersect the most
restrictive host EIRP with the primary NEPC permission and v4 ceiling; all
arithmetic retains quarter-dB units. This deliberately conservative full
profile policy also applies to v4's20MHz fallback. Current executable,
NEPC and v4 capabilities and policy are invoked on every asynchronous poll,
DMA publication and final copied IPC/stack publication. No blob, filename,
typed geometry or gain array alone proves an installed native program.

A selected peer receives HT40 only for its exact signed secondary. The
same retained PCI owner waits for full32-bit `SCH_TX_CMD` terminal, pauses
queues and closes/readbacks MAC TX/RX before programming BB and RF. The
40MHz recipe uses `0x603.2=0`, `0x800/0x900.0=1`, source `RRSR+2` primary
bits5/6, CCK0xa00.4, OFDM0xd00.10/11, FPGA0x818.26/27 and RF0x18 CENTER with
BW0x400. Twenty restores PRIMARY with BW0xc00. RF HSSI readback and BB/gain
readbacks precede reopening the actual MAC gates. The software owner enters
Failed before its first await; cancellation, source loss or failed readback
never resumes that incomplete transition.

This is a source-style same-primary width transition. Existing DMA rings,
OWN descriptors, pending allocations and receipt identities remain retained;
no BME/MAC pause is claimed as DMA reclamation. Copied capture/publication
epochs are retired before transition. Native RXD reports its original BW:
old40 cannot be admitted as20 fallback, while narrow20 reception remains
valid on the unchanged primary of a40 program. No queue contents are
relabeled. A response narrowing40 to20 completes actual20 programming
before any key/controlled-port or ordinary DATA admission. Idle channel
changes, reset and PM keep their existing full fresh-owner retirement rules.

Actual MCS DATA uses TXD DW4 BW25 plus subcarrier20/21=3. Basic legacy
management/EAPOL/control stays20MHz on the actual primary subcarrier; the
source direction chooses1 (primary lower) or2 (primary upper). Sequence,
QoS/AC, software CCMP, BA/A-MPDU and terminal OWN receipts remain owned by
the existing paths. The source HT40 INIT/LOW RA mask includes legacy OFDM6;
SGI40, MCS32,2SS, RTS/CTS and old NEFB fallback are not granted by NEHT v4.
The separate [NERT continuation](rtl8188ee-protection.md) qualifies RTS/CTS;
its source/gain checks must also remain current. Native BW/SGI checks precede PN/BA mutation; a raw BW40 bit
cannot admit40 under an actual20 receiver.

Eight cases under `drivers/wireless/rtlwifi/ht40` cover exact signed identity,
unknown rows and the center/primary factory boundary; plus/minus Open/WPA2
native DHCP/IP/descriptors; initial/response20 fallback; wrong native width
or SGI40 with valid same-PN retry; current secondary-span restrictions and
v4 revocation while DATA OWN is held; cancellation/source loss at actual
RF HSSI waits; and actual BB readback/full32-bit scheduler terminal failure.
Only hardware/MMIO/DMA and AP inputs are inert. These cases require root's
coordinated native execution; they establish no physical RF measurements.

The separate [NETH thermal continuation](rtl8188ee-tracking.md) can extend
this exact measured v4 payload with bounded gain reductions and restoration,
actual thermal IQK/LCK and a new signed full-program thermal envelope. NEHT
v4 alone retains its original static gain program and unchanged recipe.
