# drivers/wireless — Specification

> Status: **v0.2** (Stage 4 design lock).
>
> Framework for wireless drivers in the NARF ecosystem. Extends
> `drivers/spec` and `wireless/spec` to define the operational
> boundary for 802.11 hardware.

## 0. Bring-up Status (May 2026)

The following drivers have been advanced to functional bring-up
states following the May 2026 relicensing to GPL-2.0:

| Driver | Generation | Status | Mechanism |
| :--- | :--- | :--- | :--- |
| **iwlwifi** | Wi-Fi 6/6E | **Stage 3** (ALIVE) | Gen2/3 DMA, ALIVE handshake |
| **ath11k** | Wi-Fi 6E | **Stage 2** (M0) | MHI State Machine, BHI AMSS load |
| **rtw88** | Wi-Fi 5 | **Stage 2** (FW Load) | RTL8822C IDDMA, MCU handshake |

## 1. Purpose & scope

**Owns:**
- The **Wireless Driver SDK** (extending `narf-driver-sdk`).
- **Scan Offload Interface** — hardware-accelerated scanning logic.
- **WNM / RRM Hooks** — hardware-assisted network/radio resource management.
- **Hardware Queues** — mapping 802.11 Access Categories (AC_VO, AC_VI, AC_BE, AC_BK) to device rings.

**Does NOT own:**
- 802.11 MLME (Management Entity) — lives in the userspace Wireless Daemon.
- WPA Supplicant — lives in userspace.
- IP/TCP stack — lives in stack daemons.

## 2. Hardware Abstraction: The `WirelessDriver` Trait

Wireless drivers implement `WirelessDriver` (re-exported by `narf-driver-sdk`), which extends the base `Driver` trait.

```rust
#[async_trait]
pub trait WirelessDriver: Driver {
    /// Returns the hardware's supported bands and capabilities.
    fn get_hw_info(&self) -> WirelessHwInfo;

    /// Configures the hardware for a specific channel/width.
    async fn set_channel(&self, chan: ChannelCfg) -> Result<(), DriverError>;

    /// Submits a management frame for transmission.
    async fn submit_mgmt(&self, frame: Cap<DmaBuffer, Read>) -> Result<(), DriverError>;

    /// Registers a waker for received management frames.
    fn register_mgmt_waker(&self, waker: Waker);
}
```

## 3. Queue Management (Access Categories)

802.11 traffic is prioritized into four Access Categories (AC). Drivers must map these to hardware rings:

| Access Category | Description | Priority |
| :--- | :--- | :--- |
| **AC_VO** | Voice | Highest |
| **AC_VI** | Video | High |
| **AC_BE** | Best Effort | Normal |
| **AC_BK** | Background | Low |

Drivers receive traffic via four distinct Narf-Rings (one per AC) from the stack daemon.

## 4. Interaction with `narf-wireless`

- **Registration**: Drivers register via `bus::register_wireless_driver(MatchEntry { ... })`.
- **Handoff**: On successful probe, the framework mints a `Cap<WirelessIface, _>` and registers it with the global `IfaceRegistry` (see `net/spec` §3).
- **Control Path**: High-level calls like `scan()` are dispatched to the driver's `WirelessDriver` implementation.

## 5. Buffer Management

- **Data Path**: Uses standard `DmaBuffer` caps provided by `io/spec`.
- **Management Path**: Dedicated `MgmtRing` carries `DmaBuffer` caps for 802.11 management frames (Beacons, Probes, etc.).

## 6. Regulatory Enforcement

Drivers must not transmit until a regulatory domain is set.
1. The userspace Wireless Daemon reads a signed regulatory DB.
2. It sends a `SetRegulatory(CountryCode)` command to the kernel.
3. The kernel validates the signature and passes the frequency/power limits to the driver via `WirelessDriver::set_regulatory_limits()`.

## 7. Stage Assignment

- **Stage 4**: Initial framework and `WirelessDriver` trait.
- **Stage 5**: First hardware driver (MediaTek MT76 series).
- **Stage 6**: Multi-band (6 GHz), beamforming, and advanced offloads.

## 8. Dependencies

- **Consumes**: `drivers/spec`, `wireless/spec`, `bus/`, `io/`, `capabilities/`.
- **Provides to**: `narf-wireless` subsystem.
