# wireless — Specification

> Status: **v0.1** (Stage 4 design draft).
> 
> Architecture for wireless networking in the NARF ecosystem. Extends
> `net/spec` with 802.11-specific control plane, capability-gated
> scan/associate flows, and SoftMAC support.

## 0. References (public-only)

All protocol code is derived from the references below. **No GPL or
Linux `net/wireless/`, `net/mac80211/`, or vendor `wireless/`
driver source material was consulted at any point.**

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
4. **Clean-Room Drivers**: Driver implementations must follow the clean-room protocol (no GPL source).

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
