# wireless — Specification

> Status: **v0.1** (Stage 4 design draft).
> 
> Architecture for wireless networking in the NARF ecosystem. Extends
> `net/spec` with 802.11-specific control plane, capability-gated
> scan/associate flows, and SoftMAC support.

## 0. References (public-only)

The original protocol modules used the public references below. The
current nl80211 integration also uses Linux UAPI definitions, and the
iwlwifi hardware implementation uses the local Linux Intel firmware API
headers and transport source under the repository's GPL-2.0 licensing.

- **IEEE Std 802.11-2020** — Wireless LAN MAC and Physical Layer
  specifications. IEEE Standards Association.
  - §9 (Frame Formats) — drives `mlme.rs` (Frame Control,
    management headers, IE/TLV layout).
  - §12.4 (SAE) — WPA3 Simultaneous Authentication of Equals,
    referenced for future EAPOL extensions.
  - §12.7 (Keys and key distribution) — drives `eapol.rs` PRF,
    PTK derivation, and the 4-Way Handshake state machine.
- **IEEE Std 802.1X-2020** — Port-Based Network Access Control.
  §11.3 (EAPOL frame format) — drives the EAPOL header in `eapol.rs`.
- **IEEE Std 802.11-2020 §12.5.3** — CCMP (CTR-with-CBC-MAC). Drives
  `ccmp.rs`: §12.5.3.2 (CCMP header), §12.5.3.3.3 (AAD construction),
  §12.5.3.3.4 (nonce construction), §12.5.3.4.4 (replay window).
  AES-CCM block primitive is injected through the `AesCcm` trait —
  production wires AES-128-CCM from `narf-crypto`.
- **IEEE Std 802.11-2020 §9.4.2.24** — RSN Information Element.
  Drives `rsn.rs`: §9.4.2.24.1 (frame layout), §9.4.2.24.2 (cipher
  suite OUI/type table), §9.4.2.24.3 (AKM types), §9.4.2.24.4 (RSN
  Capabilities bits including MFP-required / MFP-capable / OCV).
- **IEEE Std 802.11-2020 §12.4** — Simultaneous Authentication of
  Equals (SAE / WPA3). §12.4.4 (Hash-to-Element), §12.4.5 (commit
  + confirm exchange), §12.4.7.4 (frame layout), §12.4.8.6 (state
  machine) — drives `sae.rs`. ECC group + MAC primitives are injected
  through `EccGroup` and `MacPrimitive` traits so the protocol
  state machine compiles without dragging in a bignum library;
  production wires P-256 + HMAC-SHA256 from `narf-crypto`.

## 1. Purpose & scope

**Owns:**
- The **Wireless Interface Trait** (`WirelessIface`) extending `NetIface`.
- **Wireless Capabilities** (`WirelessCap<T, R>`) for scan, associate, and monitor operations.
- **Scan/Associate Protocol** — high-level async API for discovery and connection.
- **802.11 Frame Parsing** — (SoftMAC specific) building and parsing management frames.

**Does NOT own:**
- The WPA Supplicant — WPA2/WPA3 handshakes live in a userspace daemon.
- Regulatory domain enforcement — the driver/firmware is responsible for hardware limits; the kernel validates against a signed database.
- L3+ networking — lives in stack daemons via `net/spec`.

## 2. Design Principles

1. **Microkernel-Pure**: The kernel does not contain a full 802.11 stack. Management frames are passed to a userspace "Wireless Daemon" for complex logic (MLME).
2. **Capability-Gated**: Discovery (scanning) is a distinct right from connectivity (association).
3. **Zero-Copy Hot Path**: Data frames use the standard `net/spec` Narf-Rings; management frames use a separate `MgmtRing`.
4. **Documented hardware contracts**: Record the source of firmware wire
   layouts and validate their version before use.

## 3. Public Interface

`association::{Bss, JoinPlan, SecurityMode, Phase}` supplies the shared
legacy SoftMAC management plan extracted from MT76. It validates bounded AP
IEs, SSID, supported/basic rates and Open or WPA2-PSK/CCMP negotiation, builds
open-authentication and association requests, and binds responses to the
local/AP addresses, transaction phase, status and AID. `SecurityMode` carries
no PMK. Fragmented responses (including a final fragment with nonzero
SequenceControl fragment number) leave the phase unchanged.
`append_sme_ies` accepts checked optional elements before first TX;
`legacy_rates()` returns IEEE-rate bitmaps rather than hardware indices.
`association::channel` exposes the existing 2.4/5GHz legacy 20MHz geometry.
Drivers retain their own rate-index mapping, radio/regulatory authority,
firmware peer records, retained supplicant, key installation and controlled
port. `Associated` alone grants none of those. MT76 preserves its existing
public driver API through a wrapper; RTL8188EU uses the common plan directly.

### 3.1 Interface Specialization

```rust
pub struct WirelessIfaceInfo {
    pub base: IfaceInfo,
    pub bands: Vec<WirelessBand>,    // 2.4 GHz, 5 GHz, 6 GHz
    pub modes: WirelessModes,        // Station, AP, P2P, Monitor
    pub hw_caps: HwCaps,             // HT (802.11n), VHT (ac), HE (ax), EHT (be)
}
```

`WirelessNetIface::tx_ring_for_ac(AccessCategory)` exposes separate Ethernet
producers for Background, BestEffort, Video and Voice. The default implementation
returns the ordinary `Interface::tx_ring()` for drivers with one queue.
The iwlwifi MLD implementation owns four Narf-Rings, each with an async TX
consumer and its negotiated hardware queue. AP admission control may downgrade
a class; non-WMM links use the best-effort hardware queue. The generic network
interface's `tx_ring()` remains the BestEffort ring.

`WirelessNetIface::phy_capabilities(band_mhz) -> Option<PhyCapabilities>`
returns band-specific IEEE HT (26-byte) and optional VHT (12-byte) capability
bodies. The default returns `None`. Band identifiers are 2400, 5000, and
6000 MHz. Six-GHz HE capability bodies remain driver-specific until the
generic interface grows an HE representation.
Drivers must restrict these capabilities to implemented PHY modes and their
NVM/antenna limits; `HwCaps` remains a summary. The iwlwifi Sc profile exposes
up to two streams, HT20/40 and VHT20/40/80, with firmware TX A-MPDU and host
RX Block Ack reordering. Actual association intersects AP capabilities and
regulatory permission before programming firmware.

`WirelessNetIface::supports_gtk_rekey_offload()` and
`set_gtk_rekey_data(GtkRekeyData)` model mac80211's `set_rekey_data` hook.
`GtkRekeyData` contains a 16-byte KEK, 16-byte KCK, optional AKM and the
eight-byte **big-endian** nl80211 replay counter. The generic interface never
logs or returns KEK/KCK. `NL80211_CMD_SET_REKEY_OFFLOAD` accepts this data
only on an associated, administratively-up interface; the driver retains it
until its low-power lifecycle enables firmware offload. After firmware
rekeying, `notify_gtk_rekey` multicasts the same command with only the AP MAC
and nested `REKEY_DATA_REPLAY_CTR`, matching `cfg80211_gtk_rekey_notify`.

`ScanRequest::frequencies_mhz`, `BssInfo::frequency_mhz`,
`AssociateRequest::frequency_mhz` and the userspace-SME
`MlmeAuthRequest::frequency_mhz` / `MlmeAssocRequest::frequency_mhz`
(AUTHENTICATE / ASSOCIATE's `NL80211_ATTR_WIPHY_FREQ`) are the authoritative
centre-frequency identities in MHz. `BssInfo::channel` remains the IEEE channel number for
presentation and legacy callers, but is not sufficient to distinguish 6 GHz
from the same numbered 2.4/5 GHz channels. A scan request that supplies
frequencies uses them in preference to its legacy `channels` list; an
association must retain the selected BSS's exact frequency.

`ApConfig::frequency_mhz` follows the same rule: `START_AP` retains the
exact `NL80211_ATTR_WIPHY_FREQ`, not only its derived channel number, because
6 GHz channel 1 is otherwise indistinguishable from 2.4 GHz channel 1.
`ApConfig::{channel_width,center_freq1_mhz,center_freq2_mhz}` retain the
`NL80211_ATTR_CHANNEL_WIDTH` channel definition. Drivers validate its
geometry and every constituent regulatory channel; 20/40/80/160 and 80+80
must never be silently reduced to a different on-air BSS.
`MbssidSupport` exposes a physical wiphy's
`NL80211_ATTR_MBSSID_CONFIG` maxima. When present, `START_AP` accepts the
nested MBSSID role (`INDEX`, optional self `TX_IFINDEX`, or a distinct
transmitting `TX_IFINDEX`), complete `MBSSID_ELEMS`, and EMA's matching
`EMA_RNR_ELEMS`. The generic layer validates profile count, same/different
ifindex form, EMA periodicity and complete RNR IE framing; the driver must
also verify that the named transmitter is an AP on the same physical wiphy.
`ApConfig` retains these values so the driver can form the transmitter's
ordinary or per-profile EMA beacon templates. Deleting a transmitting virtual
interface also deletes its non-transmitting profiles, as cfg80211 specifies.
`FilsDiscoveryConfig` and `UnsolBcastProbeRespConfig` retain the complete
six-GHz discovery templates supplied by `START_AP`; their 10,000-TU / 20-TU
interval and Linux frame-size bounds are checked at the netlink boundary.
`SET_BEACON` preserves per-attribute presence through
`set_ap_discovery`: an empty nested attribute is an explicit disable/delete,
while an absent attribute leaves that discovery family unchanged. A
`CHANNEL_SWITCH` may carry the unsolicited-probe form; it becomes active only
after the driver has moved the AP vdev to the requested chandef.
`FtmResponderConfig` represents the enabled nested
`NL80211_ATTR_FTM_RESPONDER` form and its optional LCI/Civic Measurement
Report bodies. A driver advertises it only when it can enable the target's
responder role; `START_AP`, `SET_BEACON`, and a post-switch beacon retain and
apply the request in their normal ordered AP transaction.
`ApConfig::twt_responder` represents START_AP's empty
`NL80211_ATTR_TWT_RESPONDER` flag. A driver advertises this only when it can
enable its AP responder role; it applies the target's pdev-wide default TWT
engine after the AP is live and disables it as the AP stops.
`HeObssPdConfig` represents `START_AP`'s nested `NL80211_ATTR_HE_OBSS_PD`
spatial-reuse policy: mandatory SR control, optional 1..=20 offsets, and the
two exact eight-byte SRG bitmaps. It is pdev-scoped target state even though
cfg80211 supplies it with one AP request; a driver applies the threshold,
per-AC and SR-prohibit settings after that AP vdev is live, followed by the
six SRG/non-SRG bitmap commands when firmware supports SRG reuse.
`HeBssColorConfig` represents the mandatory 1..=63 color plus the disabled
and partial flags of `NL80211_ATTR_HE_BSS_COLOR`. A driver that advertises
`NL80211_EXT_FEATURE_BSS_COLOR` must retain the value on `START_AP`,
`SET_BEACON`, and a post-switch beacon, and apply it only after the relevant
AP vdev start/restart. The exact firmware operation may require both
collision-detection configuration and a separate vdev color parameter; the
partial flag is retained even on targets whose WMI representation omits it.
Target collision indications are coalesced with mac80211's 500-ms rule and
published as the MLME multicast `NL80211_CMD_OBSS_COLOR_COLLISION`, carrying
the interface index and native-endian 64-bit `NL80211_ATTR_OBSS_COLOR_BITMAP`.
An MBSSID transmitter mirrors each stable color/enabled update to its live
non-transmitting profiles through their own driver-control streams, matching
mac80211's shared transmitting-BSS configuration while preserving ordered
firmware access per vdev.
`ColorChangeConfig` models AP-only `NL80211_CMD_COLOR_CHANGE_REQUEST`: it
keeps the normal post-change beacon separately from the nested temporary
countdown beacon, validates one native-endian beacon counter offset and an
optional Probe-Response offset, and retains an optional unsolicited broadcast
Probe-Response update. A BSS-color-capable driver rejects P2P-GO,
non-transmitting MBSSID, concurrent color-change and CSA requests. It emits
MLME `COLOR_CHANGE_STARTED` (with the u32 count), then `COMPLETED` after it
installs the normal template and enables the requested color; a failed queued
transition restores the retained template/color and emits `ABORTED`.
`set_beacon(head, tail)` preserves attribute presence (`None` means unchanged;
an empty supplied vector clears that template piece). `WirelessNetIface`
provides a down-only `set_iftype(NL80211_IFTYPE_*)` hook for drivers with
multiple WMI vdev roles; it must reject a type change while a vdev exists.

### 3.1.1 Physical wiphys and virtual interfaces

`WirelessNetIface::wiphy_id() -> u64` identifies the physical radio, not a
netdev. The wireless registry groups every registered interface by that id:
`GET_WIPHY` emits one physical record per group, while `GET_INTERFACE` emits
each visible netdev with that group's `WIPHY` value and an interface-unique
`WDEV` id. The default `wiphy_id` is a stable name hash for simple drivers;
multi-vdev hardware must override it with its physical-radio identity.

Drivers which can create firmware vdevs opt in through
`supports_virtual_interfaces`, `new_virtual_interface(name, iftype, mac)`,
and `delete_virtual_interface`. `NL80211_CMD_NEW_INTERFACE` is addressed to
the physical `WIPHY`; it validates the requested name, supported iftype and
unicast MAC before delegating allocation. `NL80211_CMD_DEL_INTERFACE` is
addressed to the target `IFINDEX`. It removes the interface from generic
discovery immediately; a driver whose teardown waits for firmware completes
the vdev's asynchronous stop before releasing its hardware slot. The base
physical netdev is never deletable through this virtual-interface hook.

`WirelessNetIface::station_info() -> Option<StationInfo>` supplies the
measurements `GET_STATION` may truthfully publish. `RateInfo` reports the
calculated rate in 100 kb/s plus exactly one PHY family: legacy (no MCS), HT
(`ht_mcs`), VHT (`vht_mcs = MCS, NSS`), or HE (`he_mcs = MCS, NSS, GI`, where
GI is the `nl80211_he_gi` ordinal). An HE rate also carries its explicit
`he_dcm` boolean, which nl80211 serializes as `NL80211_RATE_INFO_HE_DCM` even
when clear. `width_mhz` is 20/40/80/160 for a full channel rate. HE OFDMA
instead sets `he_ru_alloc` to the
`nl80211_he_ru_alloc` ordinal (26 through 2×996 tones); nl80211 emits
`HE_RU_ALLOC` and deliberately omits a width attribute in that case. A driver
leaves unavailable TX or RX measurements absent rather than inferring them.
`StationInfo::{tx_duration_us,rx_duration_us}`, when present, are the u64
`NL80211_STA_INFO_{TX,RX}_DURATION` aggregate PPDU airtimes in microseconds;
neither is a packet-count-derived estimate. `chain_signal_dbm` is the indexed
eight-chain `NL80211_STA_INFO_CHAIN_SIGNAL` nested array; unavailable chains
remain absent rather than being fabricated from combined signal.

`WirelessNetIface::supports_survey()` and `survey_info() -> Vec<SurveyInfo>`
opt a physical radio into dump-only `GET_SURVEY`.  Each `SurveyInfo` describes
one enabled channel and may provide its signed dBm noise floor plus the
monotonic millisecond `TIME`, `TIME_BUSY`, `TIME_RX`, and `TIME_TX` counters;
the generic layer emits only measurements the driver supplied.  It marks
`IN_USE` from the physical radio's current channel context, rather than from a
cached sample, so a record remains useful before its first hardware update.

`WirelessNetIface::antenna_info() -> Option<AntennaInfo>` publishes current
and immutable available TX/RX chain masks. `SET_WIPHY` normalizes an all-ones
TX/RX pair to those available masks, rejects zero or unavailable bits, and
calls `set_antenna(tx, rx)` only when both halves are supplied. A driver that
returns `rts_threshold()` also accepts `SET_WIPHY`'s u32 RTS value through
`set_rts_threshold`; radio-wide policies must be retained for recovery and
for later virtual-interface creation. Fragmentation threshold requests keep
the underlying driver's errno: ath11k returns `-EOPNOTSUPP` after the common
minimum-256 validation because its target firmware cannot transmit More
Fragments frames.

`TxBitrateMask` / `TxBitrateBand` carry the complete nested
`NL80211_ATTR_TX_RATES` request: the `nl80211_band` ordinal selects one band,
and optional legacy, ten-byte HT, eight-u16 VHT, GI, eight-u16 HE, HE-GI and
HE-LTF fields retain their nl80211 representation. A missing band or PHY
field means cfg80211's automatic negotiated-rate set; an empty outer list
resets every band to that default. `supports_tx_bitrate_mask` advertises
`NL80211_CMD_SET_TX_BITRATE_MASK`; its setter receives validated HT/VHT/HE
wire fields only after the netlink layer has rejected malformed field sizes,
invalid GI/LTF ordinals, duplicate nested attributes, and unsupported EHT
rate fields. A driver applies the selected active-band policy to every live
peer and retains it for new associations and hardware recovery. It must
return `-EPERM` when no channel context exists rather than guessing a band.

`WirelessNetIface::tx_power_dbm() -> Option<i32>` is the non-blocking
effective transmit-power snapshot for one netdev. When present,
`GET_INTERFACE` serializes it as `NL80211_ATTR_WIPHY_TX_POWER_LEVEL` in
signed mBm (`dbm * 100`), exactly as cfg80211's `get_tx_power` callback
result. The getter is observational only; its caller is a generic-netlink
read path and must never wait for a firmware statistics transaction.

`supports_station_tx_power()` advertises
`NL80211_EXT_FEATURE_STA_TX_PWR`; `StationTxPower` preserves the automatic,
limited-dBm, and fixed `NL80211_ATTR_STA_TX_POWER_SETTING` forms. A limited
setting requires the signed-16-bit `NL80211_ATTR_STA_TX_POWER`; a stray power
attribute without a setting is ignored as Linux's parser does. Both
`NEW_STATION`/`SET_STATION` for AP clients and `SET_STATION` on a managed
station validate the physical wiphy feature before reaching the driver. The
driver receives the named associated peer, returns its native dBm-range errno,
and retains a managed-station request for reassociation/recovery. `Fixed`
remains a distinct request because Linux ath11k accepts its enum form but
rejects the absent dBm value with `-EINVAL`.

`WirelessNetIface::{supports_four_addr_station,four_addr_enabled,set_four_addr}`
model managed-station `NL80211_ATTR_4ADDR`. `GET_INTERFACE` and interface
lifecycle replies always include the u8 state, as `nl80211_send_iface` does.
`SET_INTERFACE` accepts an enabled state only for a driver-supported station
interface (cfg80211's internal `WIPHY_FLAG_4ADDR_STATION` rule); a disable is
a harmless no-op outside station mode. A supporting driver retains the state
across association/recovery, programs its associated peer, builds
ToDS|FromDS data headers with the original Ethernet source in address four,
and sends mac80211's unencrypted 30-byte four-address Null notification when
the state becomes active.

For nl80211 scans, a nonempty nested SSID list requests active scanning;
empty SSID entries are wildcard probes and can coexist with directed SSIDs.
`CONNECT` accepts an SSID with optional BSSID/frequency constraints. It selects
the strongest matching Open/WPA2 BSS from the cache, or performs a bounded
scan first, rechecking the request's authority before association.

### 3.2 Wireless Capabilities

```rust
pub enum WirelessRight {
    Scan,        // Trigger scans, read BSSID list
    Associate,   // Connect/Disconnect from AP
    Config,      // Change channel, power, etc.
    Monitor,     // Enter monitor mode, receive all management frames
}

pub type Cap<WirelessIface, R> = ...;
```

### 3.3 Control Plane (Async)

```rust
pub async fn scan(cap: &Cap<WirelessIface, Scan>) -> Result<Vec<BssInfo>, WirelessError>;
pub async fn associate(cap: &Cap<WirelessIface, Associate>, req: AssocReq) -> Result<(), WirelessError>;
pub async fn set_phy_config(cap: &Cap<WirelessIface, Config>, cfg: PhyCfg) -> Result<(), WirelessError>;
```

### 3.4 Linux nl80211 compatibility

The wireless subsystem registers the `nl80211` generic-netlink family through
the `net/` family registry. Read-only `GET_WIPHY` and `GET_INTERFACE` point and
dump requests enumerate the canonical wireless-interface registry and emit
Linux `NEW_WIPHY` / `NEW_INTERFACE` records. Wiphy records carry a nested
band description with HT/VHT capabilities, MCS sets, HT A-MPDU factor and
density when supplied by `phy_capabilities()`. VHT is absent from the
2.4 GHz band. Capability integers use native netlink byte order; IEEE MCS
arrays retain their wire layout. A 6-GHz `WirelessBand` is emitted as
`NL80211_BAND_6GHZ` (including the 5935-MHz channel-two special case), rather
than being collapsed into or omitted from the 5-GHz record. Wiphy records also
carry a nested
`SUPPORTED_COMMANDS` list, and `GET_PROTOCOL_FEATURES` returns a zero bitmap
instead of claiming optional split-dump behavior NARF does not implement.
The family also implements `TRIGGER_SCAN`, `GET_SCAN`, `CONNECT`,
`DISCONNECT`, `SET_INTERFACE`, physical-radio `SET_WIPHY`, per-netdev
`SET_TX_BITRATE_MASK`, `GET_STATION` and range-capable `SET_CQM` (plus the userspace-SME and AP
commands below), and the `config`, `scan`, `regulatory`, `mlme`, `vendor` and
`nan` multicast groups; none of the groups carries `GENL_MCAST_CAP_*`, so any
socket may join them, as with Linux `genl_bind`.

**Permissions** follow Linux generic netlink exactly. Each `GenlOperation`
carries its `nl80211_ops` `.flags` (`narf_net::netlink_generic::
GENL_ADMIN_PERM` / `GENL_UNS_ADMIN_PERM`), reported in `CTRL_ATTR_OP_FLAGS`.
`genl_family_rcv_msg`'s order is kept: unknown family -ENOENT, op not in the
table for the requested do/dump -EOPNOTSUPP, then the permission check
-EPERM, and only then attribute validation and the device lookup
(`nl80211_pre_doit`, -EINVAL / -ENODEV). `GENL_ADMIN_PERM` needs
`netlink_capable(skb, CAP_NET_ADMIN)` — CAP_NET_ADMIN in the initial user
namespace held by both the socket's opener (`f_cred`, recorded at
`socket()`) and the sender; `GENL_UNS_ADMIN_PERM` needs
`netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN)` over the socket's
network namespace. The socket layer supplies both verdicts in
`RequestContext::{init_net_admin, net_admin}`, the same helpers rtnetlink uses.

| Command | Linux flag | NARF check |
|---|---|---|
| GET_WIPHY, GET_INTERFACE, GET_SCAN, GET_STATION, GET_PROTOCOL_FEATURES, GET_REG, GET_POWER_SAVE | none | none |
| TRIGGER_SCAN, CONNECT, DISCONNECT, SET_INTERFACE | `GENL_UNS_ADMIN_PERM` | `net_admin` or delegated handle |
| SET_KEY, NEW_KEY, DEL_KEY, SET_PMKSA, DEL_PMKSA, FLUSH_PMKSA, CONTROL_PORT_FRAME, SET_POWER_SAVE, SET_REKEY_OFFLOAD | `GENL_UNS_ADMIN_PERM` | `net_admin` or delegated handle |
| AUTHENTICATE, ASSOCIATE, DEAUTHENTICATE, DISASSOCIATE, REGISTER_FRAME, FRAME | `GENL_UNS_ADMIN_PERM` | `net_admin` or delegated handle |
| SET_BEACON, START_AP, STOP_AP, NEW/SET/DEL_STATION | `GENL_UNS_ADMIN_PERM` | `net_admin` or delegated handle |
| EXTERNAL_AUTH | `GENL_ADMIN_PERM` | `init_net_admin` or delegated handle |

A capable sender acts on any wireless interface of its own namespace with the
interface's kernel-held handle (`narf_net::kernel_admin`), so a namespace move
or removal during an asynchronous operation still revokes it. NARF's
explicitly delegated, interface-bound `AdminHandle` remains an alternative:
the generic-netlink layer lets a request carrying one through
(`RequestContext::capable == false`) and the handler then requires the handle
to cover the named interface (-EPERM otherwise, after -EINVAL / -ENODEV —
NARF-only ordering, since Linux has no such handle). Revoked, cross-interface
or cross-namespace handles are rejected; supplying an attribute never conveys
authority.

**Supplicant interop.** `GET_WIPHY` resolves its wiphy as
`__cfg80211_rdev_from_attrs` (WIPHY, WDEV or IFINDEX; none -EINVAL, not found
-ENODEV) and a dump is narrowed as `nl80211_dump_wiphy_parse` does.
`SET_INTERFACE` to the current type is a no-op. A driver that implements
`set_iftype` may change between its advertised types only while its netdev and
vdev are down; unsupported or active-vdev changes are -EOPNOTSUPP / -EBUSY.
`WirelessNetIface::cipher_suites() -> &'static [u32]` is the source of truth
for both `GET_WIPHY`'s `NL80211_ATTR_CIPHER_SUITES` and CONNECT / NEW_KEY
validation. Its default external-supplicant profile remains CCMP-128 plus
BIP-CMAC-128; a hardware driver overrides it only after its firmware key
install, data descriptor, and host MFP paths implement the advertised suite.
The ath11k WCN6855 profile supplies Linux's nine-suite set: TKIP, CCMP-128/
256, GCMP-128/256, BIP-CMAC-128/256, and BIP-GMAC-128/256.
`4ADDR` follows the selected wiphy's managed-station capability: an enabled
request needs station mode plus `supports_four_addr_station()`, while a clear
outside station mode is harmless.
`TRIGGER_SCAN` accepts `SCAN_FLAGS` FLUSH / AP / COLOCATED_6GHZ (a NARF scan
always replaces the cached results) and refuses feature-gated flags and
FREQ_KHZ with -EOPNOTSUPP, probe IEs past the advertised maximum of 0 with
-EINVAL. `CONNECT` accepts the attributes wpa_supplicant and NetworkManager
always send (`MAC_HINT`, `WIPHY_FREQ_HINT`, `BG_SCAN_PERIOD`, `PREV_BSSID`,
HT/VHT capability + mask, `CONTROL_PORT`, `CONTROL_PORT_ETHERTYPE` = ETH_P_PAE,
`CONTROL_PORT_NO_ENCRYPT`, `SOCKET_OWNER`, `EXTERNAL_AUTH_SUPPORT`, `SAE_PWE`,
`MLO_SUPPORT`, `CONTROL_PORT_OVER_NL80211`, `CONTROL_PORT_NO_PREAUTH`) with
`nl80211_connect` / `nl80211_crypto_settings`' checks; hints and overrides
steer nothing. `USE_MFP` is `enum nl80211_mfp` (REQUIRED = 1; OPTIONAL = 2
needs `NL80211_EXT_FEATURE_MFP_OPTIONAL`, which no NARF wiphy — like
mac80211 — has: -EOPNOTSUPP). A PMK needs `4WAY_HANDSHAKE_STA_PSK` and a SAE
password `SAE_OFFLOAD` (-EINVAL otherwise); pairwise / group ciphers must be
wiphy cipher suites (-EINVAL). CONNECT accepts up to five pairwise selectors,
while direct ASSOCIATE accepts one, as `nl80211_crypto_settings` does.
`CONTROL_PORT_OVER_NL80211` needs
`SOCKET_OWNER` (-EINVAL), then the ext feature (-EOPNOTSUPP). For the PMK
path the RSN element in `NL80211_ATTR_IE` must describe CCMP/PSK without
MFP-required; every element is carried in `AssociateRequest::ie`, and an
offloading driver replaces RSNE / RSNXE with its own and forwards the rest
(`ieee80211_mgd_assoc`). A successful offloaded
WPA2-PSK / SAE connect emits `CONNECT` (with `WIPHY`, `MAC`, `STATUS_CODE`)
and then `PORT_AUTHORIZED` (`cfg80211_port_authorized`), which wpa_supplicant
waits for under `WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_PSK`. `GET_SCAN` marks the
associated BSS with `NL80211_BSS_STATUS_ASSOCIATED`; `GET_STATION` reports the
AP (do needs `MAC`, -ENOENT for another peer) with the signal of its last scan
record only.

**Two driver modes.** A handshake-offloading driver (iwlwifi, mt7921)
advertises `4WAY_HANDSHAKE_STA_PSK` (and `SAE_OFFLOAD`): wpa_supplicant derives
the PMK and passes it in CONNECT, the driver's in-kernel supplicant runs the
4-way and group-key handshakes and rekeys, then PORT_AUTHORIZED. An
**external-supplicant** driver (`supports_external_supplicant()`, ath11k —
the mac80211 model) runs no supplicant: wpa_supplicant does the handshake
itself, which is also what 802.1X/EAP (WPA-Enterprise) needs. A driver that
also runs its SME in userspace (`supports_userspace_mlme()`) advertises
AUTHENTICATE / ASSOCIATE and `NL80211_FEATURE_SAE` and never the handshake
offloads (wpa_supplicant with `WPA_DRIVER_FLAGS_SME` passes no PMK yet, with
`4WAY_HANDSHAKE_STA_PSK`, ignores EAPOL), so wpa_supplicant runs SAE in
userspace over AUTHENTICATE as on Linux. The external mode is:

- **Association.** CONNECT with a protected network and neither PMK nor SAE
  password (Open System auth only), or the AUTHENTICATE / ASSOCIATE pair,
  becomes `SecurityConfig::External(ExternalSecurity { use_mfp, privacy,
  control_port })` / `MlmeAssocRequest { control_port, privacy, .. }`; the
  supplicant's RSNE / RSNXE travel in the elements. With
  NL80211_ATTR_CONTROL_PORT the port stays closed after association
  (`IEEE80211_STA_CONTROL_PORT`); without it the AP is authorized at once.
  The interface counts as connected (`connected_bssid`, `wdev->connected`)
  from association on.
- **Keys.** NEW_KEY / SET_KEY / DEL_KEY follow `nl80211_parse_key` (nested
  `NL80211_ATTR_KEY` or the old attributes, the policies' -ERANGE bounds),
  `cfg80211_validate_key_settings` (pairwise index 0 — no Extended Key ID —,
  group 0..=5, BIP index 4/5, suite-specific key / RSC lengths, and the
  selected wiphy's advertised cipher set; -EINVAL),
  `nl80211_key_allowed` (-ENOLINK unless connected), no MLO link
  (-EINVAL), then `WirelessNetIface::add_key` / `del_key` (mac80211:
  -ENOENT for a peer that is not the associated AP or a key that is not
  installed; a group key with a MAC -ENOENT). SET_KEY records a default key;
  a default-management IGTK additionally calls
  `WirelessNetIface::set_default_mgmt_key` so an AP selects the BIP transmit
  key. `KEY_MODE = SET_TX` is -EINVAL (no Extended Key ID).
- **GTK low-power rekey.** `SET_REKEY_OFFLOAD` takes nested KEK (16 bytes),
  KCK (16 bytes), replay counter (8 bytes) and optional AKM exactly as
  `nl80211_set_rekey_data` does; missing required material is -EINVAL and a
  wrong fixed length is -ERANGE. It requires an up, connected station and a
  driver that advertises the command, otherwise -ENETDOWN, -ENOTCONN or
  -EOPNOTSUPP. It retains the material for the driver's suspend/WoW path;
  it does not alter the awake userspace-supplicant Group Key Handshake.
- **Wake-on-WLAN.** `GET_WOWLAN` returns the retained
  `WirelessNetIface::wowlan_config`; `SET_WOWLAN` validates the driver
  advertised `WowlanSupport` and retains or clears a `WowlanConfig`. The
  ath11k profile accepts disconnect, magic-packet, GTK-rekey failure, and up
  to 22 masked byte patterns (each at most 128 bytes, with a same-length
  mask); unsupported trigger families are -EOPNOTSUPP and malformed nesting
  or geometry is -EINVAL/-ERANGE. Setting the configuration only changes the
  pending policy — it does not issue firmware commands while the interface is
  awake. System PM selects the retained policy at suspend: configured WoW
  preserves the associated firmware transport; absent WoW disconnects and
  cold-cycles the interface. `GET_WOWLAN` therefore reports configuration,
  not a promise that the platform is currently asleep.
- **BIOS SAR.** A driver with `WirelessNetIface::sar_capability()` includes
  its fixed range table in the nested `NL80211_ATTR_SAR_SPEC` of GET_WIPHY
  and advertises `NL80211_CMD_SET_SAR_SPECS`. The command is wiphy-wide:
  it accepts only the advertised type plus a non-duplicate subset of range
  indices and signed quarter-dBm power values, then calls
  `set_sar_power_limits`. Omitted ranges clear the host SAR limitation and a
  subsequent successful request replaces the whole target table. The driver
  retains and reapplies the resulting pdev state after a cold resume or
  firmware recovery.
- **AP vdev control.** An AP-capable driver accepts `START_AP`, `STOP_AP`,
  `SET_BEACON`, and NEW/SET/DEL_STATION only when its current iftype is AP.
  They retain the caller's ordered command in the driver's runtime queue so a
  generic-netlink syscall never re-enters the async executor. The queue runs
  each firmware transaction in order and reports a completed AP through the
  normal carrier state; a later command therefore cannot overtake its
  `WMI_VDEV_START`, beacon-template, or peer operation.
  A driver that advertises `MbssidSupport` must program its firmware's
  transmitting/non-transmitting role at vdev start, carry the transmitter
  BSSID plus profile index/count in the non-transmitting vdev-up operation,
  and retain the transmitter's complete raw MBSSID/EMA beacon family. EMA
  templates target the transmitting vdev; a non-transmitting profile waits
  for that family before its first start. Replacement templates are never
  sent to an already-up non-transmitting vdev when firmware forbids that
  sequence.
  A six-GHz driver that advertises the FILS-discovery and unsolicited broadcast
  Probe Response extended features accepts their nested templates in
  `START_AP` and `SET_BEACON`; it must apply FILS before unsolicited Probe
  Response when both intervals are nonzero, and send a zero-interval disable
  when neither is configured. A CSA-provided unsolicited-response change is
  retained until the post-switch vdev restart succeeds.
  A driver with an FTM responder role advertises
  `NL80211_EXT_FEATURE_ENABLE_FTM_RESPONDER`, accepts the enabled nested FTM
  responder form (optional LCI/Civic bodies) in AP beacon operations, and
  applies it only after the corresponding AP-vdev start/restart.
  A TWT-responder-capable AP accepts the empty `NL80211_ATTR_TWT_RESPONDER`
  flag on START_AP and, after vdev-up, enables the target's default pdev TWT
  engine. It sends the matching disable on AP stop; command failure does not
  roll a completed AP transition back.
  A driver that accepts `NL80211_ATTR_HE_OBSS_PD` validates the mandatory SR
  control and optional 1..=20 offsets / exact eight-byte bitmaps from
  `START_AP`. It applies the pdev-wide spatial-reuse state after the AP vdev
  is live, using the target's legacy non-SRG threshold form when SRG reuse is
  unavailable and its full threshold/bitmap sequence when it is available.
  A driver with HE BSS-color offload advertises
  `NL80211_EXT_FEATURE_BSS_COLOR`, validates the nested 1..=63 color and
  empty disabled/partial flags, and applies the resulting AP color only after
  the corresponding vdev start/restart. Command failures are reported without
  rolling back an otherwise complete AP transition.
  It also accepts AP-only `NL80211_CMD_COLOR_CHANGE_REQUEST`: a nested
  temporary beacon/Probe-Response countdown is active while count is above
  one, the ordinary post-change beacon then replaces it, and the requested
  color is enabled. Started/completed/aborted notifications use the nl80211
  MLME group; an active CSA and a non-transmitting MBSSID profile are refused.
  `StationConfig` preserves the associated client's legacy rates, capability
  bits, extended capability bytes, HT/VHT/HE/6-GHz capability bodies, and
  WMM indication and the nested U-APSD AC bitmap / maximum-service-period
  request. The driver intersects capabilities with its radio before peer
  association; a missing SET_STATION field leaves retained values unchanged.
  An AP-UAPSD-capable driver advertises `NL80211_ATTR_SUPPORT_AP_UAPSD`, sets
  the peer APSD/host-rate flags, then programs the target's AP-PS peer UAPSD,
  max-SP and disabled-SIFS parameters after association; target firmware owns
  client buffering and beacon TIM maintenance.
- **Station inspection.** `GET_STATION` names the connected AP for a station
  interface and names / dumps associated clients for AP or P2P GO. A client
  record includes the driver-observed AP client RX/TX MSDU, retry and failed
  completion counters plus any PPDU-backed signal, chain signal, rate and
  duration telemetry its firmware supplies.
- **Port.** SET_STATION on a station interface is `ieee80211_change_station`
  for the AP (`CFG80211_STA_AP_STA`): MAC required (-EINVAL), STA_FLAGS2
  (short -ERANGE, the invalid bit -EINVAL) or the old STA_FLAGS, -ENOENT for
  another peer, any flag but AUTHORIZED, a listen interval, an AID, rates or
  capabilities -EINVAL; then `set_port_authorized`. A supported
  `STA_TX_POWER_SETTING` additionally updates that AP peer's automatic or
  limited-power policy; the fixed ath11k form is -EINVAL.
- **PMKSA.** SET / DEL / FLUSH_PMKSA check their attributes (PMKID -EINVAL /
  short -ERANGE, MAC or the FILS triple -EINVAL) and then are -EOPNOTSUPP:
  mac80211 has no PMKSA operations; the supplicant keeps its cache.
- **EAPOL.** Received control-port frames go to the connection owner as a
  unicast NL80211_CMD_CONTROL_PORT_FRAME (WIPHY, IFINDEX, WDEV, MAC = source,
  CONTROL_PORT_ETHERTYPE, CONTROL_PORT_NO_ENCRYPT when not decrypted, FRAME
  = the PDU after the Ethernet header; `rx_control_port`, -ENOENT /
  dropped without an owner) when the association asked for
  CONTROL_PORT_OVER_NL80211 (pre-authentication frames too unless
  CONTROL_PORT_NO_PREAUTH), else up the netdev with the destination set to
  our address, where a PF_PACKET socket on ETH_P_PAE (wpa_supplicant's
  `l2_packet`) reads it. CONTROL_PORT_FRAME TX (`nl80211_tx_control_port`:
  the ext feature -EOPNOTSUPP, FRAME / MAC / ETHERTYPE -EINVAL, not
  connected -ENOTCONN; the driver: a protocol other than the association's
  or ETH_P_PREAUTH -EINVAL) requests its WBM completion under the same
  extended-ACK cookie (`NLMSGERR_ATTR_COOKIE`) unless DONT_WAIT_FOR_ACK.
  Drivers that advertise CONTROL_PORT_OVER_NL80211_TX_STATUS multicast
  CONTROL_PORT_FRAME_TX_STATUS on the MLME group when that completion arrives:
  WIPHY, IFINDEX, WDEV, the full Ethernet FRAME, COOKIE, and ACK only on a
  peer acknowledgement. The direct CONTROL_PORT_FRAME
  CONTROL_PORT_NO_ENCRYPT attribute is a per-frame
  `IEEE80211_TX_INTFL_DONT_ENCRYPT` request through the driver's TXQ. The
  same CONNECT/ASSOCIATE attribute is retained as the association policy and
  applies to ordinary netdev frames only when their EtherType equals the
  configured control-port EtherType, as mac80211 does. Either form clears the
  802.11 Protected bit even after a PTK exists. EAPOL sent through the netdev
  passes the closed port; frames otherwise leave unprotected until a pairwise
  key is installed. A local TKIP Michael MIC failure is dropped and multicast
  as NL80211_CMD_MICHAEL_MIC_FAILURE on the MLME group with WIPHY, IFINDEX,
  source MAC, KEY_TYPE, and the installed KEY_IDX when the target stripped the
  frame IV (KEY_SEQ is absent, matching cfg80211's NULL-TSC form).
- **Ordering.** The netlink syscall cannot wait for the device: these
  methods are synchronous, validate what mac80211 rejects before the driver,
  and the driver applies them on its own task strictly in request order
  (key installs, authorization, control-port TX), so M4 leaves before the
  PTK it precedes and data before the keys requested ahead of it.

**Connection owner.** `SOCKET_OWNER` on CONNECT / ASSOCIATE makes the
sender's port (`RequestContext::portid`) the connection owner
(`conn_owner_nlportid`): ASSOCIATE, DEAUTHENTICATE, DISASSOCIATE and
DISCONNECT from another socket are -EPERM, a failed connect result or a
disconnect clears it, CONTROL_PORT_FRAME RX is unicast to it, and closing
that socket (`NETLINK_URELEASE`, `narf_net::netlink_generic::notify_release`
from the socket layer) disconnects the interface
(`cfg80211_autodisconnect_wk`, reason DEAUTH_LEAVING).

**Userspace SME.** AUTHENTICATE follows `nl80211_authenticate`
(NEED_NETDEV_UP -ENETDOWN; MAC, AUTH_TYPE, SSID, WIPHY_FREQ -EINVAL; a WEP
key -EINVAL; no driver op -EOPNOTSUPP; AUTH_TYPE past SAE -EINVAL — FILS and
EPPKE are not advertised; SAE without AUTH_DATA or AUTH_DATA without SAE
-EINVAL, AUTH_DATA shorter than 4 -ERANGE; LOCAL_STATE_CHANGE a no-op; the
BSS must be in the scan results, -ENOENT; already connected to it
-EALREADY). The driver's answer is published as NL80211_CMD_AUTHENTICATE
(WIPHY, IFINDEX, FRAME) or, on timeout, with TIMED_OUT + MAC. ASSOCIATE
follows `nl80211_associate` (owner -EPERM, SSID -EINVAL, a
non-inheritance element -EINVAL, USE_MFP other than NO / REQUIRED -EINVAL,
HT/VHT overrides without masks -EINVAL, MAC + WIPHY_FREQ -EINVAL, the
scan entry -ENOENT, crypto settings, connected to another BSS -EALREADY);
when PREV_BSSID is present it must identify the associated BSS displaced by
this SME authentication; the driver emits a Reassociation Request with that
current-AP address and accepts only a Reassociation Response. If the AP
rejects it, NARF retries once as a plain Association Request before reporting
the denial, as cfg80211's SME does;
the response is published as NL80211_CMD_ASSOCIATE (FRAME, REQ_IE = the
SME's elements) followed by the CONNECT result. A temporary status-30
response carrying Timeout Interval type Association Comeback instead emits
NL80211_CMD_ASSOC_COMEBACK (WIPHY, IFINDEX, MAC and TIMEOUT in TUs), leaves
the connection owner intact, and lets the supplicant schedule the next
ASSOCIATE; it does not publish CONNECT. DEAUTHENTICATE /
DISASSOCIATE need MAC and a non-zero REASON_CODE (-EINVAL); DISASSOCIATE
while not connected to that BSS is -ENOTCONN. A driver that reports its own
disconnects publishes DEAUTHENTICATE / DISASSOCIATE with the frame and then
DISCONNECT for every loss (`notify_mlme_disconnect`; wpa_supplicant's SME
ignores DISCONNECT and acts on the DEAUTHENTICATE frame).

**Other commands.** GET_REG returns the global domain (the installed
deployment policy, else cfg80211's `world_regdom`), or with WIPHY that
wiphy's own (`regulatory_domain()`); the dump lists the global domain then
each wiphy domain with WIPHY and WIPHY_SELF_MANAGED_REG. SET_POWER_SAVE /
GET_POWER_SAVE need `power_save_default()` (mac80211's `set_power_mgmt`,
else -EOPNOTSUPP), keep `wdev->ps` (on by default,
CONFIG_CFG80211_DEFAULT_PS) and call the driver only on a change; PS_STATE
missing -EINVAL, past ENABLED -ERANGE. GET_INTERFACE carries
NL80211_ATTR_WDEV (`wiphy << 32 | 1`). GET_STATION's STA_INFO carries what
`station_info()` tracks (signal, average / ACK signal, indexed chain signal,
TX / RX bitrate with `nl80211_put_sta_rate`'s attributes, packet / retry /
failure counters, and RX / TX PPDU duration), the scan record's signal
otherwise. A driver leaves an unavailable measurement absent rather than
synthesising one.

`SET_CQM` accepts the station/P2P-client RSSI form: a binary native-endian
signed threshold array plus its required native-endian u32 hysteresis. Values
must be non-positive and strictly increasing. A zero/empty array disables it;
a multi-value array requires CQM_RSSI_LIST. The software mac80211 path uses
the associated AP's four-sample 1/16-dBm beacon EWMA. A singleton evaluates
the configured threshold and hysteresis; a list maintains the adjacent
low/high interval around the last CQM level and re-centres it after each
crossing. It multicasts `NOTIFY_CQM` with nested threshold-event and RSSI-level
attributes after releasing its driver lock.

When `supports_ack_signal()` is true, `EXT_FEATURES` carries
ACK_SIGNAL_SUPPORT and `GET_STATION` may carry the last successful TX ACK's
signal in `NL80211_STA_INFO_ACK_SIGNAL`; it remains absent until a valid
completion provides it.

When `supports_scan_dwell()` is true, `EXT_FEATURES` carries SET_SCAN_DWELL.
`TRIGGER_SCAN` accepts native-endian `MEASUREMENT_DURATION` (u16 TUs) and its
zero-length `_MANDATORY` flag. The request retains both; ath11k applies a
nonzero duration to every active/passive WMI dwell field and bounds its scan
timeout with Linux's per-channel event-overhead calculation.

`TRIGGER_SCAN` additionally accepts up to 512 bytes of `NL80211_ATTR_IE`,
matching `WLAN_SCAN_PARAMS_MAX_IE_LEN`. On an active ath11k scan these are
appended after the host's standard Probe Request rates/capabilities and sent
as WMI's extra-IE array; longer input is -EINVAL.

`WirelessNetIface::nl80211_feature_flags()` returns only defined physical
`NL80211_FEATURE_*` bits; the generic wiphy response combines them with its
SME and random-MAC bits. ath11k exposes AP-vif scans, AP in-place channel
width changes, firmware TPC report power insertion, and static SMPS. It adds
dynamic SMPS only when the negotiated firmware HT capability has
`WMI_HT_CAP_DYNAMIC_SMPS`.

An AP-capable driver may expose `max_ap_assoc_sta()`; a nonzero value is
serialized as `NL80211_ATTR_MAX_AP_ASSOC_STA`. It is an advertised physical
limit rather than a reservation: concurrent firmware peer use can still make
an individual `NEW_STATION` fail, as cfg80211 permits.

`iftype_extended_capabilities()` returns the cfg80211 default and explicit
per-role Extended Capabilities records. nl80211 serializes each as an
`IFTYPE`, `EXT_CAPA`, and equally long `EXT_CAPA_MASK` triplet nested under
`NL80211_ATTR_IFTYPE_EXT_CAPA`. `wiphy_extended_capabilities()` independently
supplies the top-level `EXT_CAPA`/`EXT_CAPA_MASK` pair. Malformed unequal
records are omitted.
ath11k supplies Linux's default, station, and AP records for extended channel
switching, MBSSID, operating-mode notification, TWT requester/responder, and
EMA capability.

`wiphy_mac_addresses()` supplies a multi-vdev radio's preallocated address
pool; a pool with more than one member is emitted as nested
`NL80211_ATTR_MAC_ADDRS`, alongside the physical base `MAC`. A nonzero
`max_csa_counters()` advertises `MAX_CSA_COUNTERS`; a driver that can send
management frames on an active off-channel ROC context sets
`OFFCHANNEL_TX_OK` through `supports_offchannel_mgmt_tx()`.

The common wiphy discovery fields retain Linux/mac80211 defaults unless a
driver exposes a mutable implementation: retry-short = 7, retry-long = 4,
coverage class = 0, and a disabled fragmentation threshold (`u32::MAX`).
ath11k exposes the latter state while rejecting a threshold change, and
retains its separately mutable RTS threshold.  WoW network-detect discovery
uses the UAPI's exact u8 (`MAX_NUM_SCHED_SCAN_SSIDS`/`MAX_MATCH_SETS`) and
u16 (`MAX_SCHED_SCAN_IE_LEN`) payload widths.

`GET_SURVEY` is a dump operation when `supports_survey()` is true.  Every
`NEW_SURVEY_RESULTS` reply contains its IFINDEX and one nested
`NL80211_ATTR_SURVEY_INFO` record with `FREQUENCY`, optional `NOISE`,
`IN_USE`, and the available survey-time attributes.  A driver may use an
ordered asynchronous control worker for a target refresh: its dump returns
the last complete physical-radio snapshot and queues one coalesced refresh,
instead of re-entering an IRQ/WMI completion wait from the generic-netlink
handler.  Consequently the next dump observes the completed refresh; callers
must not interpret a missing time field as a zero counter.

An ath11k low-power owner calls its MAC's GTK-offload helper at the WoW
boundary: enable serializes WCN6855's `WMI_GTK_OFFLOAD_CMDID` with the saved
KEK/KCK and a little-endian firmware replay counter; resume first requests
status, then disables the engine. `WMI_GTK_OFFLOAD_STATUS_EVENTID` updates the
saved counter and publishes the big-endian nested replay counter above. The
registered async system-PM hook programs all WoW triggers/offloads and waits
for the HTC suspend acknowledgement before MHI M3; it restores M0 plus CE/DP
delivery, waits for the WMI host-wakeup event, then removes temporary state.
Without a retained WoW configuration it follows cfg80211/mac80211's normal
disconnect plus cold HIF/MHI reset/reconfigure route instead.

Driver coverage: ath11k implements the external mode, the userspace SME,
power save, its regulatory domain and completion-backed STA_INFO signal, ACK
signal, TX / RX packet, failure and retry counters. Its first-MSDU TQM WBM
completion decodes a TX bitrate (legacy / HT / VHT / HE, including HE OFDMA
RUs) with the association's negotiated NSS, while its fast-RX descriptor
decodes the received packet type / MCS / GI / bandwidth / stream bitmap into
RX bitrate. Fast RX has no HE RU allocation, so an HE RX rate reports its full
received bandwidth (matching `ath11k_dp_rx_h_rate`). Both descriptor mappings
still await on-card qualification. iwlwifi and mt7921
stay handshake-offload drivers: their firmware paths run the handshake
themselves, so they do not claim `supports_external_supplicant()` (NEW_KEY
and the other external commands are -EOPNOTSUPP from nl80211, and a
`SecurityConfig::External` reaching them is `WirelessError::NotSupported`);
they ignore `AssociateRequest::ie` (their firmware builds the Association
Request) and have no SET_POWER_SAVE.

Deviations kept: a NEW_KEY whose firmware install fails is reported to the caller as success
(the driver applies it after the syscall returned); the ASSOCIATE event's
REQ_IE is userspace's elements, not the whole frame body mac80211 built;
NARF's older attribute helpers answer a short fixed-size attribute with
-EINVAL where the policy says -ERANGE (the new commands use -ERANGE).

Mutating requests validate attributes, reserve one operation per interface,
then run the native async method in the executor. Netlink ACK acknowledges
acceptance; completion is a scan-results/aborted, connect-status, or
disconnect event. Cancellation releases the operation reservation. Scan
dumps are bounded to 256 BSS records and preserve original AP information
elements through `WirelessNetIface::scan_information_elements`.
Interface and wiphy queries are namespace-filtered; events use the same
namespace and cannot follow an interface across a namespace move.
Drivers that implement `reports_disconnect_events()` emit link-loss and
local-teardown notifications themselves through
`notify_disconnect(name, reason, from_ap)` (`nl80211_send_disconnected`:
`REASON_CODE` omitted when 0, `DISCONNECTED_BY_AP` when the AP sent the
Deauthentication / Disassociation), so the control bridge does not emit a
second local-disconnect event.

### 3.4.1 CCMP packet helpers (`ccmp.rs`)

`build_aad` authenticates the three addresses, fragment number and optional
Address4 / QoS TID. It excludes Duration/HT Control, mutes data subtype bits
4–6 (preserving the QoS indicator), Retry/PM/MoreData and QoS Order, and
forces Protected. Management subtype and non-QoS Order remain authenticated.
`build_nonce` includes the transmitter address and big-endian 48-bit PN.
`protect` / `unprotect` take an `AesCcm` backend; `unprotect` checks a copy of
`ReplayWindow` and commits it only after MIC verification. Authentication
failure leaves ciphertext and replay state unchanged when the backend honors
its verify-before-mutation contract. The caller must validate complete MAC
header bounds, key role/ID, native station addresses, nonce uniqueness and
PN exhaustion, and retain independent replay trackers per key/TID (including
a separate non-QoS tracker). These helpers do not grant controlled-port access.

### 3.5 EAPOL supplicant (`eapol.rs`)

`Supplicant` runs the 4-way handshake (`handle`) and, once it completed,
the Group Key Handshake: `process_group_m1(pdu, mic_len, group_key_len,
mgmt_group_key_len)` applies wpa_supplicant's `wpa_sm_rx_eapol` checks
(length, descriptor, replay counter, SMK / Ack / Request bits, descriptor
version 2 or 3, MIC by `eapol_key_mic`, AES-unwrapped Key Data) and
`wpa_supplicant_process_1_of_2` (GTK KDE, length = group cipher key
length, IGTK KDE only with PMF, key-reinstallation check), and returns the
keys plus the 2/2 PDU (802.1X version 1, Key Info = key index | version |
Secure | MIC). `GroupKeyError::Drop` = ignore the frame,
`GroupKeyError::Fail` = deauthenticate (`WLAN_REASON_UNSPECIFIED`). The
caller installs the keys, then calls `group_keys_installed`.

The connect profile requires a scanned BSSID, SSID and 2.4/5 GHz frequency.
Open networks need no key. WPA2 requires a 32-byte PMK, WPA version 2,
PSK AKM, and CCMP-128 pairwise/group suites. Drivers opt in through
`supports_handshake_offload()`; only those advertise the PSK four-way
handshake offload feature. Required MFP, other ciphers/AKMs, arbitrary
association IEs, random scan MACs and other unsupported mutation options
are rejected. Scan execution is passive. Full wpa_supplicant/iw process
interoperability remains a separate integration test.

### 3.5 Deployment regulatory policy

`reg::parse_policy` decodes an NRGD v1 policy; parsing alone conveys no
authority. The iwlwifi probe optionally opens `wireless-regulatory.bin`
through its trusted firmware-registry capability. It installs the policy
only after the registry verifies its signature and the view identifies a
signer. Unsigned policies are rejected even in unsigned-firmware builds.
Deployment public keys are baked into the image with
`NARF_FIRMWARE_TRUSTED_KEYS`; the firmware packer accepts a verified
detached signature. No deployment country or signing key is chosen by
the driver. The policy must be supplied by the image builder.
Without a configured policy the interface may scan passively but cannot
associate. This is a deployment-selected policy, not a bundled global
regulatory database or a country inferred from AP advertisements.

The byte format is `NRGD[4]`, version `u16=1`, uppercase country `[u8;2]`,
rule count `u16`, reserved `u16=0`, followed by 1–64 rules of 16 bytes:
start MHz `u32`, end MHz `u32`, maximum bandwidth MHz `u32`, power dBm
`i8`, `RegFlags` `u8`, reserved `u16=0`. Integers are little-endian;
unknown flags, malformed ranges and length mismatches are rejected.
The driver intersects the selected host rule with firmware MCC permission
and applies its power ceiling before transmitting association frames.

For Stage 5 bring-up the iwlwifi driver currently hosts the station MLME
and WPA2 state machine behind `WirelessNetIface`. The intended daemon
split described below has not yet replaced that implementation.

## 4. Architecture: SoftMAC vs. FullMAC

NARF supports both through the `WirelessIface` trait:

- **FullMAC Drivers**: The firmware handles scan/associate state machines. The driver implements the high-level `associate()` call by sending a command to hardware.
- **SoftMAC Drivers**: The hardware only does radio/PHY. The driver/kernel/daemon must handle the 802.11 MAC management.
  - In NARF, SoftMAC logic is split:
    - **Driver**: Timing-critical frames (ACKs, Beacons where possible).
    - **Wireless Daemon (Userspace)**: MLME (Association, Authentication, Reassociation).
    - **Narf-Link**: Management frames are routed to the Daemon via a dedicated `MgmtRing`.

## 5. Security: The Wireless Daemon

Following the `net/spec` §8.5 "Stack-daemon trust" model:
- WPA2/WPA3 (SAE) encryption/decryption happens in hardware where possible.
- Key management and the 4-way handshake happen in the **Wireless Daemon**.
- The Daemon holds `Cap<WirelessIface, Associate>` and `Cap<WirelessIface, Config>`.

## 6. Zero-Copy Management Path

Management frames (Beacons, Probe Requests) are voluminous.
- A `Monitor` cap allows a process to open a `MgmtRing`.
- `MgmtRing` carries `DmaBuffer` caps pointing to raw 802.11 frames.
- No copy between hardware → driver → daemon.

## 7. Stage Assignment

- **Stage 4**: Initial design and `narf-wireless` crate skeleton.
- **Stage 5**: First clean-room driver (candidate: MediaTek MT76 or Atheros AR9271).
- **Stage 6**: Multi-band support, WPA3 integration.

## 8. Resolved Decisions

### 8.1 No MLME in Kernel (Resolved)
**Decision**: The 802.11 MLME (Media Access Control Sublayer Management Entity) state machine is too complex and bug-prone for the Frame. It lives in userspace. The kernel only provides the mechanism to send/receive management frames.

### 8.2 Hardware-Agnostic Scan (Resolved)
**Decision**: Drivers implement a unified `scan()` async call. If the hardware supports "Offload Scan", the driver uses it. If not, the driver performs the channel-hopping and probe-sending manually in the driver domain.

## 9. Dependencies

- **Consumes**: `net/` (base interface), `drivers/`, `capabilities/`, `ipc/`, `io/`.
- **Provides**: Wireless-specific control plane to userspace daemons.
