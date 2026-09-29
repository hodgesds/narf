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
`SUPPORTED_COMMANDS` list, and `GET_PROTOCOL_FEATURES` returns a zero bitmap
instead of claiming optional split-dump behavior NARF does not implement.
The family also implements `TRIGGER_SCAN`, `GET_SCAN`, `CONNECT`, and
`DISCONNECT`, plus the `config`, `scan`, and `mlme` multicast groups.
Mutations require an explicitly delegated `AdminHandle` for the selected
interface in the requesting socket's namespace. Missing, revoked,
cross-interface or cross-namespace authority is rejected. Opening a Linux
socket or supplying an attribute does not convey this authority.

Mutating requests validate attributes, reserve one operation per interface,
then run the native async method in the executor. Netlink ACK acknowledges
acceptance; completion is a scan-results/aborted, connect-status, or
disconnect event. Cancellation releases the operation reservation. Scan
dumps are bounded to 256 BSS records and preserve original AP information
elements through `WirelessNetIface::scan_information_elements`.
Interface and wiphy queries are namespace-filtered; events use the same
namespace and cannot follow an interface across a namespace move.
Drivers that implement `reports_disconnect_events()` emit link-loss and
local-teardown notifications themselves through `notify_disconnect`, so
the control bridge does not emit a second local-disconnect event.

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
