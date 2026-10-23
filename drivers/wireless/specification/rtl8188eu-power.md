# RTL8188EU signed board power qualification

This contract is part of [rtl8xxxu §3](rtl8xxxu.md#3-public-interface).

`power_policy::Calibration::load_registered(factory, vid, pid)` opens only
`rtl8xxxu/rtl8188eu-cal-v1-<12 lowercase MAC hex digits>.bin` through the
current firmware-registry capability. The registry verifies the signature
against its trusted signer store; the driver additionally requires nonempty
signer metadata even when the development profile permits unsigned firmware.
The private byte decoder cannot mint a production calibration directly.
Verified bytes are copied into bounded owned curves before the blob cap is
released. The signer and registry payload digest remain available to driver
diagnostics. This is calibration evidence, not a device-access capability;
all actual USB accesses still use the retained generation-checked device.

The payload is N8PC v1. Integers are little endian. The 64-byte header contains:

| Offset | Value |
|---|---|
| 0 | magic `N8PC` |
| 4 | version:u16 = 1 |
| 6 | header bytes:u16 = 64 |
| 8 | exact total payload bytes:u32 |
| 12 | USB VID:u16 |
| 14 | USB PID:u16 |
| 16 | chip:u16 = 0x8188 |
| 18 | checked silicon cut:u8 |
| 19 | profile:u8 = 1 (RTL8188EU USB, 1T1R, legacy20, no runtime power tracking) |
| 20 | factory MAC[6] |
| 26 | all retained factory CCK gain bases[6] |
| 32 | all retained factory HT40 gain bases[5] |
| 37 | crystal cap:u8 |
| 38 | channel plan:u8 |
| 39 | thermal factory byte:u8 |
| 40 | board option:u8 |
| 41 | envelope:u8 = 1 (whole qualified board operating envelope) |
| 42 | maximum antenna gain:i16, quarter-dBi, 0..128 |
| 44 | board-qualified maximum EIRP:i16, quarter-dBm, -512..256 |
| 46 | channel rows:u16, 1..13 |
| 48 | reserved[16] = zero |

Each 260-byte row is channel:u8 (1..13), reserved[3]=zero, CCK[64]:i16,
OFDM[64]:i16. Rows must have strictly increasing channels. Each curve entry
is a conservative conducted-power upper bound in quarter-dBm for that exact
gain index; 0x7fff means unqualified/unknown and is never interpolated.
Qualified values are -512..256. The CCK envelope covers all four legacy CCK
rates, and the OFDM envelope covers all eight legacy OFDM rates. The profile
does not authorize HT/MCS. The complete payload is at most 3444 bytes.

Envelope1 requires the signer to qualify bounds over the exact board,
antenna, frequency and supported supply/temperature/manufacturing range,
with the driver's RF tables, full LC/IQK result and disabled thermal power
tracking. A single room-temperature power measurement is insufficient.
Cable/connector loss and negative antenna gain receive no power credit.
The artifact is tied to every retained Factory field plus USB VID/PID,
chip/cut/profile; another chip or a replacement device cannot reuse it.

`Calibration::permission(authenticated_domain, channel)` returns an opaque
fixed-channel gain token. Current runtime channel1 only is admitted. Every
regulatory rule overlapping 2402..2422MHz must cover the complete 20MHz
channel, allow 20MHz and contain no unsupported flags. The most restrictive
rule's dBm ceiling is treated conservatively as an EIRP ceiling and intersected
with board-qualified EIRP. For each modulation class the driver selects only
an explicitly qualified index at or below the exact factory base, whose
conducted upper bound plus maximum antenna gain does not exceed that ceiling.
Quarter-dB arithmetic never rounds power down. Missing curves, unmeasured
points, identity mismatch, unsigned/missing artifacts, unsupported policy or
insufficient low-power qualification keep MAC TX closed; there is no default
curve or gain-index-to-dBm inference. The native radio owner must revalidate
the token's identity/channel before programming gains and opening TX.

Remaining physical input: acquire and qualify a per-device/board conservative
power envelope and antenna bound, sign it with a trusted firmware-registry
key, and install the exact MAC-bound artifact. No real curve is provided by
this change. Synthetic test curves validate dimensional/policy arithmetic
only. Linux's RTL8188EU fops calls rtl8188f_set_tx_power, programming raw CCK
and HT40 bases; its parser populates no per-rate differences and rtl8xxxu
provides no dBm conversion. RTL8188EE's separate index conversion is not used.
