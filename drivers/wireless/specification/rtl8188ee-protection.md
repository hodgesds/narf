# RTL8188EE signed RTS/CTS full-program qualification

This is part of [rtlwifi §3](rtlwifi.md#3-public-interface). The NERT v1
continuation and six native cases are implemented pending coordinated
release compilation and final native validation. No board measurements,
physical control-frame observations or signed deployment data are supplied.

The existing NEPC and NEHT programs exclude RTS/CTS emissions. NERT is a
separate optional signed extension over the exact current factory/NEPC,
retained executable and measured NEHT payload (or legacy program). It
qualifies the complete unchanged gain program with RTS, CTS-to-self and
all hardware control retry rates. It does not reinterpret NEPC/NEHT or
increase their gain, antenna, channel, width or EIRP rights.

After initial Passive service has selected its actual program,
`RtlwifiDevice::rts_cts_request()` returns the exact filename and recipe
binding with no radio I/O. The filename is
`rtlwifi/rtl8188ee-rts-cts-v1-<12 lowercase MAC hex digits>-p<primary>-s<secondary>-h<profile>.bin`.
Secondary is0 for a20MHz program; profile is0 for legacy,2 for NEHT v2,
3 for v3 or4 for v4. The exact measured NEHT payload SHA256 is required,
including v4's full20/40 program when its actual receiver uses20 fallback.
A recipe hash alone cannot substitute another measured HT payload.
The registry verifies the signature and the driver requires nonempty trusted
signer metadata even under development unsigned-firmware policy.

The NERT v1 payload is1472 bytes, with little-endian integers:

| Byte range | Value |
|---|---|
| 0..4 | magic `NERT` |
| 4..6 | version:u16 = 1 |
| 6..8 | header bytes:u16 = 192 |
| 8..12 | total bytes:u32 = 1472 |
| 12..16 | PCI VID0x10ec, DID0x8179 |
| 16..48 | NERT recipe SHA256 returned by the request |
| 48..80 | canonical exact factory SHA256 |
| 80..112 | exact preceding NEPC payload SHA256 |
| 112..118 | repeated factory MAC |
| 118..124 | primary, full-profile width20/40, streams1, mode-mask3, secondary-or0, center |
| 124..126 | maximum antenna gain:i16, quarter-dBi |
| 126..128 | qualified EIRP ceiling:i16, quarter-dBm |
| 128..160 | exact measured NEHT payload SHA256, or zero for legacy |
| 160..192 | zero |
| 192..1472 | ten rows of64 conducted-peak upper bounds:i16, quarter-dBm |

Rows0/1 cover all CCK/OFDM rates, including autonomous RTS/CTS retries.
Rows2–9 cover MCS0–7 when the underlying native HT program is present;
these rows cannot create HT rights on a legacy owner. Every raw index0–63
is a known bound in -512..256 quarter-dBm or unknown (`i16::MAX`). Unknown
points grant nothing; no interpolation or monotonic raw-index assumption
is made. The antenna bound must be at least both preceding NEPC and NEHT
bounds and at most128 quarter-dBi. The signed ceiling is -512..80
quarter-dBm. Each selected actual legacy/MCS gain must fit the new row
plus antenna, current host ceiling, NEPC ceiling and existing NEHT ceiling.
V4 additionally retains its complete occupied40MHz policy, center/primary
factory bounds and both actual20/40 states. No raw gain is changed by NERT.

Measurements must bound the complete static factory antenna/IQK/LCK,
supply/manufacturing/thermal0..63 program, all ordinary/automatic/control
emissions and retries, including SGI20 and wide LGI when the exact NEHT
payload admits them. A single room-temperature point is insufficient.
Missing optional data leaves the unprotected source behavior available only
where protection is not required. Unsigned, foreign or malformed present
data fails; an unknown/insufficient row refuses before authentication TX.
A revoked NERT source never falls back to an unprotected required frame.

Policy follows pinned Linux7.2 `mac80211/tx.c`, `rate.c` and
`rtlwifi/base.c::_rtl_query_protection_mode`. ERP Use_Protection requests
CTS-to-self for OFDM/MCS; CCK DATA retains its existing long-preamble form.
`WirelessNetIface::set_rts_threshold(bytes)` on the native Device or PCI
wrapper implements the actual nl80211 SET_WIPHY setting. Values0–2347
request RTS/CTS for unicast DATA MPDUs whose actual length plus FCS exceeds
the threshold; `u32::MAX` is the disabled source default. GET_WIPHY reports
the retained value. Invalid values return EINVAL without mutation; an enabled
setting on a live peer requires current NERT and OFDM24 support. The setting
belongs to the physical device and survives station reset and replacement
owner recovery; it never grants a replacement owner RF rights. RTS takes precedence over CTS. The threshold
also applies to EAPOL DATA; authentication, association and BA management
frames keep their source management profile. Required protection refuses
an AP rate set without OFDM24 support. HT operation protection modes that
the retained owner already refused remain outside this explicit ERP/threshold
policy; no new mapping is inferred from their numeric values.

Actual RTL8188EE TXD DW4 carries initial RTS rate8 (OFDM24), CTS-to-self
bit11 or RTS-enable bit12 exclusively. HW-RTS13, RTS-SHORT26, RTS-BW27,
RTS-SC28/29 and RTS-STBC30/31 remain clear, matching the source. The existing
DW5 RTS retry/fallback limit15 remains intact. DATA bandwidth/primary SC,
SGI20, sequence, QoS/AC, CCMP and BA/A-MPDU fields remain independently
owned. Protected DATA keeps DISFB; old NEFB does not qualify a new combined
fallback/protection emission sequence. The hardware produces control
frames from these actual descriptors; the host does not synthesize PPDU
success, ACKs or a substituted DMA receipt.

The current NERT capability encloses actual native OWN/doorbell publication,
asynchronous peer/RA/key/M4 polls and final copied IPC/stack publication,
alongside the existing executable/NEPC/NEHT/PCI/current-policy proofs.
Threshold changes serialize with the publication gate, and the selected
mode is reread at actual publication. Live bound native beacons update ERP
before subsequent DATA; ordinary TX waits until the receive walk observes
an actual OWN-owned idle descriptor, so an unprocessed ERP update beyond
one receive budget cannot be overtaken. Reassociation/recovery resolves a
new exact current source tuple. Failure/cancellation retains published DMA;
no protection grant proves reclamation of a held descriptor.

Six native `drivers/wireless/rtlwifi/protection` cases exercise exact signed
identity/measurement/unknown bounds; legacy/HT Open/WPA2 ERP CTS with real
kernel DHCP and IP; threshold boundary/RTS precedence; HT40 descriptor and
software-security composition; refusal before authentication when measured
data is absent or unknown; and live ERP changes plus revocation while the
actual native M4 OWN is held. Only hardware/DMA/AP and dimensional signed
metadata are inert. The cases are written but unexecuted; physical RF
interoperability and power qualification remain external gates.

The separately signed [NETH thermal continuation](rtl8188ee-tracking.md) can
extend this exact measured NERT payload with bounded TXAGC reductions and
restoration. NERT v1 alone keeps its original unchanged gain program. Its
format and recipe are unchanged; NETH requires the exact NERT payload digest,
new full-thermal/full-program measurements and all preceding actual raw-gain
curves and ceilings.
