# RTL8188EE signed thermal TXAGC full-program qualification

This is part of [rtlwifi §3](rtlwifi.md#3-public-interface). The NETH v1
continuation and six composed native cases are implemented pending coordinated
release compilation and final native validation. No board measurements,
thermal measurements, signed deployment assets or physical RF acceptance
are supplied. Existing NEPC, NEHT and NERT formats and recipes are unchanged.

The optional NETH record qualifies the complete actual private EE program:
its exact factory map, retained executable, NEPC payload, measured NEHT payload
if present, and measured NERT payload if present. NEPC/NEHT alone continue to
exclude thermal tracking. NERT alone adds protection with unchanged gains.
NETH cannot add an antenna, channel, width, rate, protection mode or larger
factory/host/preceding measured gain. It permits thermal reductions and
restoration inside all preceding bounds. Old NEFB is excluded while this
continuation is installed; it did not qualify the combined tracking/fallback
program.

After Passive service has selected the actual private program,
`RtlwifiDevice::thermal_tracking_request()` returns its filename and recipe
SHA256 without radio I/O. It consults the current optional NERT registry
record for the same private program; provisioning NERT first is necessary
when the desired program uses RTS/CTS. Factory thermal EFUSE byte0xba must
be1–63. Erased, zero or out-of-range inputs are refused instead of substituting
Linux's EEPROM default. The filename is
`rtlwifi/rtl8188ee-thermal-v1-<12 lowercase MAC hex digits>-p<primary>-s<secondary>-h<profile>-r<protection>.bin`.
Secondary is0 for a20MHz program; profile is0 for legacy,2 for NEHT v2,
3 for v3 or4 for v4. Protection is0 without NERT and1 with NERT. V4 always
binds the full signed20/40 program, including actual20 fallback. Registry
signature verification and nonempty trusted signer metadata are mandatory.

The NETH v1 payload is82176 bytes, with little-endian integers:

| Byte range | Value |
|---|---|
|0..4 | magic `NETH` |
|4..6 | version:u16 =1 |
|6..8 | header bytes:u16 =256 |
|8..12 | total bytes:u32 =82176 |
|12..16 | PCI VID0x10ec, DID0x8179 |
|16..48 | NETH recipe SHA256 returned by the request |
|48..80 | canonical exact factory SHA256 |
|80..112 | exact preceding NEPC payload SHA256 |
|112..118 | repeated factory MAC |
|118..124 | primary, full-profile width20/40, streams1, mode1, secondary-or0, center |
|124..126 | maximum antenna gain:i16, quarter-dBi |
|126..128 | artifact EIRP ceiling:i16, quarter-dBm |
|128..160 | exact measured NEHT payload SHA256, or zero for legacy |
|160..192 | exact measured NERT payload SHA256, or zero without protection |
|192..196 | repeated factory thermal byte, thermal-count64, rate-family-count10, gain-count64 |
|196..256 | all zero |
|256..82176 |64 thermal planes, each10 rows of64 signed:i16 conducted upper peaks |

Thermal plane order is raw meter0–63. Row order is CCK, OFDM, then MCS0–7;
gain order is0–63. Every known bound is in−512..256 quarter-dBm;
`i16::MAX` denotes unknown. Antenna gain is at least every preceding bound
and at most32dBi; the artifact ceiling is in−128..20dBm. Each admitted raw
gain needs a known bound in **every** thermal plane. The driver takes the
maximum of all64 planes; one unknown leaves that gain unknown. No
interpolation, monotonicity, dBm estimate or recent sample fills a hole.
The parser retains1280 bytes of maxima, rather than an82KiB stack buffer.

These are full-program peak bounds. Each populated cell must cover every
ordinary/automatic/control/retry emission, LGI/SGI20, the full measured
HT20/40 and20 fallback program, software-crypto/QoS/BA operation, and actual
IQK/LCK tones and transients. It must cover all permitted transitions from
any other admitted operating point, including the initial nominal point,
all intermediate TXAGC/BB/RF/calibration states, supply range and the static
factory antenna. A measured DATA-only peak is insufficient. Measurements
must also cover the complete physical operating range associated with all
meter values, sensor/averaging lag and unsampled movement. This conservative
all-plane check prevents autonomous responses or a stale sample from
escaping a thermal-dependent envelope between watchdog steps.

The actual source chain is pinned Linux7.2
`rtl88e_dm_check_txpower_tracking` → `dm_txpower_track_cb_therm` →
`dm_tx_pwr_track_set_pwr(TXAGC)` → `rtl88e_phy_set_txpower_level` →
`rtl88e_phy_rf6052_set_{cck,ofdm}_txpower`. The2s watchdog alternates a real
RF42[17:16]=3 trigger and a real RF42[15:10] sample. Trigger bits are a
command; the driver does not invent a sticky completion receipt. Zero
samples fail closed. The last four nonzero values are averaged exactly;
EEPROM0xba supplies the factory reference. CCK table columns2–5 are matched
against the actual0xa24 readback for the original swing index. Source
thermal-threshold and swing-offset tables select the new CCK swing index.

The EE `rf.c` calls `rtl88e_dm_txpower_track_adjust(type=1)` for both CCK
and OFDM/MCS TXAGC. Thus this path uses the CCK swing-index difference for
all supported rates. It does not install the alternative BB-swing tables.
The driver applies signed per-rate arithmetic with saturation, preventing
packed-word carry/borrow from creating another rate's gain. A source-requested
increase is capped by the original current qualified indices; it can restore
a prior reduction but cannot boost beyond them. Every actual resulting
CCK/OFDM/MCS index must fit the original factory maxima, NEPC, measured NEHT,
NERT if present, the full host40MHz span when v4 is retained, the new NETH
all-plane peak, and every antenna/EIRP ceiling. Unknown lower gains refuse
an update; a smaller index alone is not proof of smaller conducted power.

When the averaged sample drifts by at least8 from the last calibration
reference, actual retained LCK/IQK run again. Ordinary packet admission waits
for a host TX receipt and no pending security/control DATA. The transition
pauses all queues, waits for the actual full SCH_TX_CMD0x5f8 value to become
zero, closes ordinary MAC TX/RX, then runs calibration and programs TXAGC.
The real RF18 primary/center/width and RF0 mode, IQK matrix and saved BB/MAC
state, actual gains, unused2SS zeros, MAC gates and queue pause are read back
before reopening. Width, rates, peer, keys, PN history, BA/reorder ownership,
DMA rings and original OWN receipts stay with their actual owners. Receive
identity does not change with TX gain; copied tokens retain the same current
full-program authority, and ordinary DATA waits for a fresh receive-idle pass.

Every native poll and final TX/copy/IPC/stack publication invokes the actual
retained firmware/NEPC/NEHT/NERT/NETH capabilities again and checks current
host policy. Revocation, missing peaks, policy change, ignored gain writes,
missing scheduler idle or bad calibration fail closed. Cancellation during
an RF wait marks the retained preparation Failed; no default operating point,
forged calibration result or DMA receipt reopens it. A disassociated owner
may retain a qualified reduced point while Passive. A subsequent join uses
fresh current authority to restore the original point before selecting a new
peer's width and qualification. Recovery creates a fresh owner and must
resolve its actual measurements again.

Six new `drivers/wireless/rtlwifi/tracking` cases use actual
Firmware/PacketIo/Prepared/Device, native DMA/peer/security fixtures and the
kernel DHCP client: signed identity and all-plane holes; Open/WPA2 legacy
and HT DHCP/IP with literal source reduction and average4 restoration;
plus/minus HT40, response20 fallback and actual RTS fields; real IQK/LCK
measurement/restoration; invalid qualification/sensor/write/scheduler/
calibration failures; and revoked held M4 plus cancelled RF waits retaining
actual ownership. They are written but have not executed. Coordinated
release compilation and final native/full-matrix validation remain required.

Dynamic antenna selection is a separate feature. Linux EE does implement
CGCS_RX_HW_ANTDIV, CG_TRX_HW_ANTDIV and CG_TRX_SMART_ANTDIV. This thermal
continuation retains the current static factory/OEM path and grants no
per-antenna selection authority. Exact per-antenna measurements and the
antenna descriptor/receive-statistics/calibration owner remain necessary
for that separate continuation.
