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
| **iwlwifi** | AX210+ transport; Sc/BE211 MLD station profile | RX/TX and station implementation; silicon validation pending | Firmware self-load, RFH, command/data queues, Open/WPA2-PSK |
| **ath11k** | Wi-Fi 6E | **Stage 2** (M0) | MHI State Machine, BHI AMSS load |
| **rtw88** | Wi-Fi 5 | **Stage 2** (FW Load) | RTL8822C IDDMA, MCU handshake |

## 1. Purpose & scope

**Owns:**
- The **Wireless Driver SDK** (extending `narf-driver-sdk`).
- **Scan Offload Interface** — hardware-accelerated scanning logic.
- **WNM / RRM Hooks** — hardware-assisted network/radio resource management.
- **Hardware Queues** — mapping 802.11 Access Categories (AC_VO, AC_VI, AC_BE, AC_BK) to device rings.

**Target split:** MLME and the WPA supplicant belong in a userspace
Wireless Daemon. The current iwlwifi MLD bring-up path implements the
station state machine inside the driver behind `WirelessNetIface`.
Moving it across the management-frame interface remains follow-up work;
the present implementation must not be described as a userspace supplicant.

**Does NOT own:**
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

### 3.1 Implemented iwlwifi MLD station profile

The production Gen3 probe owns firmware/IML/PNVM bytes and schedules
initialization in executor context. It registers `wlan0` only after ALIVE,
PNVM, PHY initialization, NVM reading, and MAC/link configuration succeed.
Firmware command versions are checked before version-specific layouts are
used. The Sc/BE211 profile implements `WirelessNetIface` as follows:

- `get_wireless_info()` reports the real hardware MAC and NVM-enabled
  2.4/5 GHz channels and station mode. NVM antenna masks and SKU flags
  constrain HT/VHT to at most two spatial streams; MIMO-disabled SKUs
  advertise one. `phy_capabilities(band_mhz)` supplies HT capability bodies
  for 2.4/5 GHz and VHT for 5 GHz to nl80211 and active probe templates.
  HE/EHT are not advertised. HT registration requires supported firmware
  Block Ack command/notification versions.
- `scan()` runs bounded passive or active scans, applies SSID/channel filters,
  and retains at most 256 BSS records. Association selects a matching
  cached BSSID/SSID/channel. Active scans emit wildcard or up to 20 directed
  probes, allowing hidden-SSID discovery. Only channels permitted for active
  transmission by both the signed host policy and firmware MCC receive a
  probe bitmap; DFS and disallowed channels remain passive. The lowest
  applicable power limit is programmed before scanning. Without a host
  policy all channels remain passive.
- `associate()` configures a negotiated PHY/link/peer, allocates management
  and data queues, authenticates, and associates. Supported/basic rates are
  intersected with the AP; mandatory unsupported PHY/rate selectors are
  rejected. HT supports 20/40 MHz and VHT supports 20/40/80 MHz, with
  common MCS masks, short guard intervals, peer LDPC reception, SMPS and
  HT protection programmed into TLC v6, peer and link commands. VHT MCS9
  is excluded at 20 MHz for the supported one/two-stream profile.
  Association responses confirm capabilities and can narrow the negotiated
  profile. A subsequent beacon that changes the negotiated PHY constraints
  closes the controlled port and requires reassociation; live channel/PHY
  migration is not implemented. All occupied 20 MHz channels and the complete channel span must
  satisfy host and firmware regulatory limits, including bandwidth and power;
  the response's final span is revalidated. TLC v6 adapts data rates within
  that intersection. WMM negotiation
  enables BK/BE/VI/VO hardware queues with AP EDCA parameters and QoS headers.
  DSCP classifies kernel traffic; explicit AC rings preserve daemon priorities.
  Categories requiring admission control downgrade to an admitted category.
  Association supports Open, WPA2-PSK, and WPA3-Personal (SAE) with
  CCMP-128. WPA3 runs the SAE (H2E, group 19) commit/confirm exchange in
  the driver, derives the PMK, and completes the AKM-SAE 4-way handshake
  (SHA-256 KDF-Length PTK, AES-128-CMAC EAPOL-Key MIC, Key Descriptor
  Version 0). The IGTK from message 3 is installed into a BIP-CMAC-128 key
  store (`wireless::mfp`): group-addressed robust management frames are
  MMIE-verified on receive and a forged or unprotected deauthentication /
  disassociation is dropped instead of tearing down the link (the 802.11w
  forged-broadcast-deauth defense), and the station's own disassociation is
  sent with the Protected bit set. WEP and TKIP remain unsupported. A configured host regulatory domain and
  firmware MCC permission are required before transmission. The selected
  rule's power ceiling is applied through the firmware power command.
- WPA2 authenticates the original EAPOL PDU before changing key/replay
  state. Pairwise/group keys are installed in firmware. Repeated M3
  messages cannot reinstall keys, and repeated GTK material cannot reset
  RX counters. RX checks MIC status and per-TID packet numbers before
  delivering plaintext Ethernet. The controlled port opens only after
  key installation and message-4 TX completion. Group and pairwise rekey are
  supported. A new pairwise challenge uses a fresh SNonce and keeps the active
  PTK until authenticated M3 succeeds. Key replacement drains TX and discards
  RX captured across the transition before
  resetting replay state. Identical key material is never reinstalled.
- HT/VHT TX A-MPDU setup and retries are firmware-managed. Compressed BA
  notifications retire validated cumulative TX intervals. RX immediate
  Block Ack sessions negotiate up to 64 MPDUs per TID, with at most eight
  sessions. ADDBA/DELBA, firmware BAID v2 allocation/removal, BAR and frame
  release notifications drive host reordering across 12-bit sequence wrap.
  Holes release after 100 ms; nonzero negotiated inactivity timeouts tear
  down sessions. Authentication/admission precedes buffering; ordered
  delivery advances CCMP packet numbers. Key changes discard buffered
  old-key MPDUs. Repeated ADDBA requests preserve an existing matching
  session. Control work is bounded and restricted to the associated AP.
  Firmware-deaggregated standalone A-MSDUs require ordered subframe indices;
  equal PNs are allowed only within the same key's aggregate. A-MSDU inside
  A-MPDU and host TX A-MSDU construction are not negotiated.
- `disassociate()` closes the port, removes RX BA sessions, drains TX,
  removes TX queues and the peer,
  deactivates/detaches the link, and removes the PHY. Cancellation or a
  transport error leaves the interface down; the next scan/associate
  resets hardware before accepting another operation.
- `set_config()` currently accepts the already-associated channel with
  no power override. Channel changes require reassociation; explicit
  runtime power overrides return `NotSupported`.

The best-effort Ethernet path is registered with both the capability frame
registry and the kernel interface registry. It converts Ethernet and
unfragmented 802.11 frames after any required reordering/deaggregation.
Synchronous network waits can
drain RX without polling the executor recursively. Background work uses an
async mutex and MSI-X completion waits with bounded watchdog timers; it does
not hold an IRQ-safe lock across an await. RX queue 0 and non-RX causes use
separate MSI-X table entries sharing one owned host vector. The hard IRQ
acknowledges/rearms and latches error causes; the task drains DMA. Waits
snapshot the IRQ count before reading completions, including command waits
that own the async mutex. Each of the four TX tasks waits on its Ethernet
ring's waker and retains accepted frames while waiting for hardware queue
credit. Credit waits drain DMA under the async mutex and fail the transport
after a bounded timeout; only validated completions release descriptors.
Shutdown masks device and PCI delivery and synchronizes handlers
before releasing their cookie/vector; restart restores IVAR/UMAC routing.
160/80+80 MHz, HE/EHT, 6 GHz, roaming, and suspend/resume remain outside
this station profile (advanced PHY/offloads are assigned to Stage 6).

### 3.2 DMA lifetime and completion contract

AX210 uses 32-byte RFH completions; Bz/Sc uses 4-byte completions. Both use
16-byte transfer descriptors and buffer IDs rather than completion order.
Only published IDs may be completed, and a buffer is reposted only after
its packet has been copied. Fragment chains are discarded as a unit.
Descriptor writes precede doorbells through a DMA visibility barrier.

Command and data payloads remain allocated until a validated completion.
Command replies must match the outstanding command and sequence; unsolicited
notifications cannot reclaim command DMA. Legacy TX responses advance
exactly one owned descriptor. Aggregated queues accept cumulative compressed
BA and single-frame retry completions. Every queue/station/TID and every
reclaimed descriptor is validated before any DMA is released; malformed
multi-queue reports cannot partially reclaim buffers. A timeout never frees
DMA on its own.
Reset/drop releases resources only after the hardware DMA-stop handshake
and PCI bus-master disable succeed; otherwise allocations are quarantined.
Firmware sections, boot context, scratch, and PNVM remain owned throughout
the running device's lifetime.

These contracts have QEMU software regression tests. QEMU does not emulate
the target Intel radio: successful DMA, RF operation, AP association and
IP traffic on BE211 still require silicon validation. The existing Gen2
probe is separate and does not inherit the MLD station implementation.

Validation on 2026-09-29: full QEMU suites returned 8,905 pass / 0 fail /
79 skip on x86_64 and 6,725 pass / 0 fail / 40 skip on aarch64. After the
final SSID-connect and TX-credit changes, focused wireless/control suites
returned 522 pass / 0 fail / 7 skip on x86_64 and 231 pass / 0 fail / 0 skip
on aarch64. Both
production boot smokes and btrfs interoperability postflights passed, as
did debug/release builds on both architectures. The host xtask suite
passed all 66 tests; trusted-key build-parser tests passed both cases.
Formatting and Clippy on the affected kernel libraries and xtask passed.
These results validate software contracts, not target-radio operation.

## 4. Interaction with `narf-wireless`

- **Registration**: Drivers register via `bus::register_wireless_driver(MatchEntry { ... })`.
- **Handoff**: On successful probe, the framework mints a `Cap<WirelessIface, _>` and registers it with the global `IfaceRegistry` (see `net/spec` §3).
- **Control Path**: High-level calls like `scan()` are dispatched to the driver's `WirelessDriver` implementation.

The implemented high-level control trait is `narf_wireless::WirelessNetIface`.
The `nl80211` family bridges explicitly delegated scan/connect/disconnect
requests to this trait and publishes asynchronous completion events.
Probe can load a signed `wireless-regulatory.bin` deployment policy via the
firmware registry (wire format in `wireless/` §3.5). A trusted service launcher
uses `net::stack::control_registered` with its interface/daemon capabilities,
then `userspace::network_daemon::prepare` (or
`spawn`) with the loaded executable. This grants the service's ordinary
netlink sockets without attaching the L3 frame path to XDP. Executable
selection and boot service policy belong to the launcher. Actual supplicant
interoperability, provisioned policy and target hardware still require an
end-to-end integration run.

A `wireless/nl80211` regression test (`smoke_nl80211_supplicant_interop`)
replays the exact exchange `wpa_supplicant` drives through libnl —
`CTRL_CMD_GETFAMILY("nl80211")`, `GET_WIPHY`, `GET_INTERFACE`,
`TRIGGER_SCAN`/`NEW_SCAN_RESULTS`, `GET_SCAN`, `CONNECT`, `DISCONNECT` —
through the production generic-netlink dispatcher and multicast event sink
against a mock offload station, asserting the family id, the scan/mlme group
ids (18/19), the advertised commands/cipher/ext-features, and the connect and
disconnect event payloads. All command, attribute, nested sub-attribute,
cipher/AKM suite, ext-feature and errno values are validated against
`/usr/src/linux` `include/uapi/linux/nl80211.h` (6.17-rc2). This proves the
software contract a supplicant depends on; it is not a silicon test.

WPA3-Personal (SAE) is wired through the same control plane. A driver that
sets `WirelessNetIface::supports_sae_offload()` advertises
`NL80211_EXT_FEATURE_SAE_OFFLOAD`, and `CONNECT` decodes the SAE attribute set
(`NL80211_ATTR_SAE_PASSWORD`, AKM `00-0F-AC:8`, SAE auth, required MFP, CCMP)
into `SecurityConfig::Wpa3`, selecting a WPA3 BSS and emitting the connect
event (`smoke_nl80211_wpa3_sae_connect`). The iwlwifi station profile
implements this end to end: it advertises SAE offload, runs the SAE
commit/confirm exchange (`wireless::sae`, H2E group 19) as algorithm-3
Authentication frames, and completes the AKM-SAE 4-way handshake
(`security::Akm::Wpa3Sae`: SHA-256 KDF-Length PTK, AES-128-CMAC MIC, Key
Descriptor Version 0). The IGTK is installed and 802.11w management-frame
protection is enforced on the management RX/TX paths via `wireless::mfp`
(BIP-CMAC-128 MMIE verification of group-addressed robust frames, dropping
forged/unprotected deauth/disassoc). The SAE exchange honors an AP's
anti-clogging-token request (status 76), echoing the token in an H2E
Anti-Clogging Token Container element on a bounded Commit retry.

Roaming is supported: a connect request targeting a different BSS of the
current ESS (`WirelessNetIface::connected_bssid` differs from the target) is
routed through `WirelessNetIface::roam`, which reassociates — a Reassociation
Request carrying the previous AP address, re-auth, and a fresh 4-way handshake
with the new AP — and the control plane publishes an `NL80211_CMD_ROAM` event
rather than `CONNECT`. MMIE *emission* for AP/group-addressed TX and SAE-PK
(public-key validation) remain follow-up work; as with the rest of this
profile, these paths are validated by software contract tests, not against
target silicon.

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
