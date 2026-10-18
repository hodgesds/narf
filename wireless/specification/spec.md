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
bodies. The default returns `None`. Band identifiers are 2400 and 5000 MHz.
Drivers must restrict these capabilities to implemented PHY modes and their
NVM/antenna limits; `HwCaps` remains a summary. The iwlwifi Sc profile exposes
up to two streams, HT20/40 and VHT20/40/80, with firmware TX A-MPDU and host
RX Block Ack reordering. Actual association intersects AP capabilities and
regulatory permission before programming firmware.

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
arrays retain their wire layout. Wiphy records also carry a nested
`SUPPORTED_COMMANDS` list, and `GET_PROTOCOL_FEATURES` returns a zero bitmap
instead of claiming optional split-dump behavior NARF does not implement.
The family also implements `TRIGGER_SCAN`, `GET_SCAN`, `CONNECT`,
`DISCONNECT`, `SET_INTERFACE` and `GET_STATION` (plus the userspace-SME and AP
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
| SET_KEY, NEW_KEY, DEL_KEY, SET_PMKSA, DEL_PMKSA, FLUSH_PMKSA, CONTROL_PORT_FRAME, SET_POWER_SAVE | `GENL_UNS_ADMIN_PERM` | `net_admin` or delegated handle |
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
`SET_INTERFACE` to the current type is a no-op; a real type change, or
`4ADDR`, is -EOPNOTSUPP (no driver implements `change_virtual_intf`).
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
wiphy cipher suites (-EINVAL). `CONTROL_PORT_OVER_NL80211` needs
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
  group 0..=5 with AES-CMAC advertised, AES-CMAC index 4/5, key / RSC
  lengths, the wiphy's cipher suites CCMP + AES-CMAC; -EINVAL),
  `nl80211_key_allowed` (-ENOLINK unless connected), no MLO link
  (-EINVAL), then `WirelessNetIface::add_key` / `del_key` (mac80211:
  -ENOENT for a peer that is not the associated AP or a key that is not
  installed; a group key with a MAC -ENOENT). SET_KEY sets default /
  default-management keys (accepted, no driver call, as mac80211's
  `set_default_key`); `KEY_MODE = SET_TX` is -EINVAL (no Extended Key ID).
- **Port.** SET_STATION on a station interface is `ieee80211_change_station`
  for the AP (`CFG80211_STA_AP_STA`): MAC required (-EINVAL), STA_FLAGS2
  (short -ERANGE, the invalid bit -EINVAL) or the old STA_FLAGS, -ENOENT for
  another peer, any flag but AUTHORIZED, a listen interval, an AID, rates or
  capabilities -EINVAL; then `set_port_authorized`.
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
  or ETH_P_PREAUTH -EINVAL) returns a cookie in the extended ACK
  (`NLMSGERR_ATTR_COOKIE`) unless DONT_WAIT_FOR_ACK. EAPOL sent through the
  netdev passes the closed port; frames leave unprotected until a pairwise
  key is installed.
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
the response is published as NL80211_CMD_ASSOCIATE (FRAME, REQ_IE = the
SME's elements) followed by the CONNECT result. DEAUTHENTICATE /
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
`station_info()` tracks (signal, average / ACK signal, TX / RX bitrate with
`nl80211_put_sta_rate`'s attributes, packet counters), the scan record's
signal otherwise.

Driver coverage: ath11k implements the external mode, the userspace SME,
power save, its regulatory domain and STA_INFO signal. iwlwifi and mt7921
stay handshake-offload drivers: their firmware paths run the handshake
themselves, so they do not claim `supports_external_supplicant()` (NEW_KEY
and the other external commands are -EOPNOTSUPP from nl80211, and a
`SecurityConfig::External` reaching them is `WirelessError::NotSupported`);
they ignore `AssociateRequest::ie` (their firmware builds the Association
Request) and have no SET_POWER_SAVE.

Deviations kept: CONTROL_PORT_OVER_NL80211_TX_STATUS is not advertised (no
CONTROL_PORT_FRAME_TX_STATUS; wpa_supplicant uses it only as an AP); a
NEW_KEY whose firmware install fails is reported to the caller as success
(the driver applies it after the syscall returned); the ASSOCIATE event's
REQ_IE is userspace's elements, not the whole frame body mac80211 built;
reassociation (PREV_BSSID) through the userspace SME is not implemented;
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
