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
| GET_WIPHY, GET_INTERFACE, GET_SCAN, GET_STATION, GET_PROTOCOL_FEATURES | none | none |
| TRIGGER_SCAN, CONNECT, DISCONNECT, SET_INTERFACE | `GENL_UNS_ADMIN_PERM` | `net_admin` or delegated handle |
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
`MLO_SUPPORT`) with `nl80211_connect`'s checks; hints and overrides steer
nothing. For the PMK path the RSN element in `NL80211_ATTR_IE` must describe
CCMP/PSK without MFP-required; other elements are accepted and not forwarded.
`CONTROL_PORT_OVER_NL80211` is -EOPNOTSUPP (the ext feature is not
advertised), so EAPOL never reaches userspace. A successful offloaded
WPA2-PSK / SAE connect emits `CONNECT` (with `WIPHY`, `MAC`, `STATUS_CODE`)
and then `PORT_AUTHORIZED` (`cfg80211_port_authorized`), which wpa_supplicant
waits for under `WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_PSK`. `GET_SCAN` marks the
associated BSS with `NL80211_BSS_STATUS_ASSOCIATED`; `GET_STATION` reports the
AP (do needs `MAC`, -ENOENT for another peer) with the signal of its last scan
record only.

**WPA2-PSK with wpa_supplicant / NetworkManager** therefore runs on the
handshake-offload path every NARF station driver implements (ath11k, iwlwifi,
mt7921): wpa_supplicant derives the PMK and passes it in `CONNECT`, the
driver's in-kernel supplicant runs the 4-way and group-key handshakes and
rekeys. There is no external-supplicant driver mode: `NEW_KEY` / `SET_KEY` /
`DEL_KEY`, `SET_PMKSA` / `FLUSH_PMKSA`, `SET_STATION(AUTHORIZED)` on a station,
`CONTROL_PORT_FRAME` and EAPOL delivery to `PF_PACKET` are not implemented
(-EOPNOTSUPP; wpa_supplicant ignores each on this path). They are what
802.1X/EAP (WPA-Enterprise) or a supplicant-run 4-way handshake would need: a
`WirelessNetIface` mode that hands EAPOL frames to the netdev RX ring and
transmits them unencrypted before authorization, a key-install method, and
an authorize-port method, with the driver's in-kernel supplicant (including
its group rekey) disabled for that association. `SOCKET_OWNER` is accepted
but closing the owner socket does not disconnect.

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
