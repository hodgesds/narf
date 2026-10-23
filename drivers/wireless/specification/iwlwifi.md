# iwlwifi — Specification

> Status: **v0.5** (AX210+ transport and Sc MLD station profile;
> target hardware validation pending).
>
> GPL-2.0-or-later driver for Intel PCIe wireless host controllers
> (AX200 / AX201 / AX210 / AX211 / AX411, Bz/BE200 and Sc/BE211).
> Adapted directly from Linux `drivers/net/wireless/intel/iwlwifi/`
> source.

## 1. Purpose & scope

**Owns:** Bring-up and operational control of Intel AX2xx/BE2xx-class
radios. Implements `narf_net::Interface` and
`narf_wireless::WirelessNetIface`.

The current Gen3 runtime includes AX210/Bz/Sc transport initialization and
an MLD station profile. The separate Gen2 probe remains gated; existing
software tests do not establish hardware acceptance for either path.

**Does NOT own (any stage):** mac80211-equivalent stack,
802.11 frame parsing/building (lives in `narf_net`), regulatory
domain handling.

## 2. Hardware Interface

### 2.1 CSR (Control / Status Registers)
Directly mapped at the base of BAR0. Used for device reset,
interrupt masking, and gating firmware loading.

### 2.2 PRPH (Peripheral Window)
Indirect access via `HBUS_TARG_PRPH_WADDR` / `_RDAT` / `_WDAT`.
Reaches the internal peripheral register file.

### 2.3 DMA Rings
- **RX**: Single descriptor ring (RXB) mapped in coherent host
  RAM. Drain is managed by the `iwl_rx_pump` task.
- **TX**: Multiple scheduler rings. Queue 0 used for management
  commands and background `iwl_tx_pump`.

### 2.4 Host Commands (HCMD)
Communication with the firmware uses a Group-Command-Version
addressing scheme. Commands (e.g., `SCAN_REQ_UMAC`) are enqueued
as TFDs with a specific command header.

### 2.5 ALIVE Handshake
After making boot DMA visible and enabling DMA/interrupts, the runtime
publishes the context and IML addresses and sets `CSR_AUTO_FUNC_BOOT_ENA`.
It must then release the embedded CPU: AX210 writes `UREG_CPU_INIT_RUN=1`
through the 32-bit UMAC peripheral window at `0xd05c44`; Bz/Sc writes
`CSR_FUNC_SCRATCH=0x01010101` before setting `CSR_GP_CNTRL.ROM_START` (bit
7). Both control-register updates preserve existing ownership, clock and
access bits. Automatic function boot alone does not release the CPU.
The same sequence applies after a transport restart.

The driver waits asynchronously for the DMA-delivered `ALIVE` notification
(status `0xCAFE`) with a bounded timeout. Exact register order, address
width and preservation of existing control bits have software regressions;
successful ALIVE and subsequent radio operation still require silicon
validation. Reference: Linux
`pcie/gen1_2/trans-gen2.c::iwl_trans_pcie_gen2_start_fw` and
`pcie/ctxt-info-v2.c::iwl_pcie_ctxt_info_v2_kick`.

### 2.6 Post-init runtime configuration

After `INIT_COMPLETE` and NVM/antenna discovery, the live station runtime
sends Linux's BT coexistence defaults (`BT_CONFIG` v6: network coexistence,
MPLUT and high-band retention), the PCI-profile-specific
`SOC_CONFIGURATION` v2, and `POWER_TABLE` v7 with continuously awake mode.
Sc uses integrated-device flags, low-latency XTAL, a 12,000 µs stabilization
latency and 2,500 µs LTR delay; the discrete BE200 configuration keeps the
discrete flag and has no integrated LTR delay. Unknown PCI profiles or
command versions fail initialization instead of choosing defaults from the
RX descriptor format. Recovery replays these commands before recreating
the station interface. RX queue zero is configured by the boot context;
additional RX queues and RSS remain disabled for this single-queue profile.

The supported software profile is a single station with Open/WPA2-PSK or
WPA3-SAE security, 2.4/5 GHz, and legacy/HT/VHT operation up to 80 MHz.
Gen2/MVM station operation, AP mode, 6 GHz/HE/EHT and system suspend/resume
still require separate software implementations. They are not hardware-only
acceptance gates and are not enabled by this profile's station tests.

## 3. Public interface and stage progression

- **Stage 1**: PCI match table.
- **Stage 2**: CSR/PRPH mapping + APM init + ucode header parsing.
- **Stage 3**: Owned Gen3 firmware loading and DMA ALIVE handshake. Gen2
  context-v1/RFH/TFH and retained API77 MVM boot ownership are implemented;
  MVM station context/security/scan lifecycle remains an explicit software dependency.
- **Stage 4**: Interface traits, IPC ring integration, background
  RX/TX pumps, and the MLD station scan/association/data implementation.
- **Stage 5 (In progress)**: First hardware boot/ALIVE, firmware init,
  scan, station association and IP-traffic acceptance. Software tests
  exercise these contracts without emulating the Intel radio.

### 3.1 Native PCI and current authority

Probe reserves one PCI function, leaves repeated owned-BDF dispatch untouched,
and parks additional candidates. It clears inherited bus mastering and memory
decode and verifies INTx disabled before BAR sizing, maps BAR0 with Device
attributes, then verifies decode enabled with bus mastering still off. Unsupported
Gen2 candidates remain parked: the old FH diagnostic loader cannot establish a
working AX200/AX201 lifecycle and never publishes a synthetic station identity.

Every native CSR/PRPH-window dword read/write executes inside `Cap::invoke` and
checks the complete aligned BAR extent. Revoked/invalid reads return the gone
sentinel and writes do nothing. RX publication/draining, host commands and data
submissions check current authority before mutating device-visible ownership.
PCI bus-master transitions require command readback. MSI-X mapping, configuration
and enable/disable also execute inside invocation; if revocation prevents proving
interrupt delivery disabled, teardown retains the vector reservation. These checks
prove current-operation admission, not atomic exclusion of concurrent revocation.

The diagnostic `PollingAliveSink::new(region,cap)` uses bounded scheduler polling,
rejects gone/revoked reads and requires its observed status; an interrupt bit alone
cannot manufacture a successful ALIVE. The live Gen3 path still requires the exact
DMA notification and supported command versions described above. Real object-table
revocation fixtures exercise native dword bounds and actual RX/command/data queues.

### 3.2 Shared synchronous/asynchronous runtime progress

Ordinary TX has one retained packet and a two-second credit deadline per access
category, with the four IPC consumers owned by device state. The common bounded
step drains RFH completions first and attempts at most one packet per category.
Lack of credit keeps the original packet and sequence number; no async task holds
the state mutex while waiting for ordinary TX credits. Closed carrier, disconnect
and recovery clear pending and queued packets before later station admission.

EAPOL/key replacement and receive-aggregation commands retain a complete,
driver-owned future. Both executor polls and synchronous network drains poll the
same future before attempting device-state access. A dropped external waiter
does not drop firmware/DMA/key ownership, and unrelated control operations return
Busy while another caller owns state. Key work remains exclusive until terminal
completion; errors fail the transport and close carrier. Existing TX drain,
key-install completion, RX discard and replay-reset ordering is preserved.

Each hardware Activity wait yields at least once, including when its IRQ/timer
is already ready, so one retained-future poll cannot loop indefinitely through a
continuous IRQ stream. The pump re-enters common progress on IPC/control wakes.
Roam closes packet admission before replacing the previous peer/queue/key owner;
a failed old disconnect prevents a new association until transport recovery.

Tests cover retained waiter cancellation, bounded pending-packet retries, and
actual Device.step over RFH/DataQueue completions: a full TX queue still delivers
RX, validated credit resumes the exact pending packet, disconnect clears queued
data, and an independent WPA2 M1 advances through a retained EAPOL TX receipt
using synchronous drains after its async waiter is dropped. These are software
ownership regressions and do not emulate radio or establish silicon acceptance.

### 3.3 One-shot interface publication

Publication claims the device once before changing IPC endpoints. Missing or
revoked network authority, an occupied interface name or capability-registry
failure rejects startup while every new channel remains private. Successful
capability registration is required before ACTIVE, the kernel netdev and workers
appear. No later fallible step releases that published ownership. Repeated calls
fail before replacing the live RX/TX endpoints; a failed attempt requires a fresh
device owner. Real-cap revocation/missing-authority, duplicate-call and
post-staging registry-failure fixtures exercise the actual publication entry
without publishing an interface or worker.

### 3.4 Retained 22000 / API77 MVM boot

A separate Gen2 owner implements the context-v1 transport for exact AX200
2723 and AX201 02f0/43f0/a0f0 MAC/RF profiles. It selects Linux's CC/Qu/QuZ
firmware prefix from discovered identity and requires API77 and the negotiated
ALIVE6/NVM4 command profile. Native automatic admission remains closed: MVM
station MAC/PHY/binding, rate/key/Block-Ack, scan and recovery lifecycle still
need integration before a Gen2 interface can be published.

The transport retains its 1792-byte context, all LMAC/UMAC/paging sections,
command ring and Qu RFH allocations. Context-v1 uses 8-byte page-address/tag
free entries and 4-byte low12-ID completions. TX uses the 20-byte v9 command
and DWORD byte counts; RX MPDUs use the separate 48-byte v1 envelope.
Mappings are checked for alignment, tag bounds and 4GiB self-load boundaries.
It does not borrow the Gen3 IML/scratch bootstrap.

Gen2 native preparation has a one-shot phase before the first register
operation. BME stays verified off through ownership/reset, protected
persistence handling, integrated forced-gating or discrete AX200 BISR,
L0s/clock workarounds, firmware PHY configuration and shadow registers.
Actual interleaved PRPH apertures and 20-bit/width-encoded addressing are
used throughout. Retained context publication precedes ROM LTR programming
and CPU release. ALIVE6's packed extent is checked, then unified NVM init
requires INIT_EXTENDED_CFG(NVM), NVM_ACCESS_COMPLETE and INIT_COMPLETE.
Nonzero SKU does not select the Gen3 external PNVM sequence.

`mvm_boot::Owner` retains the exact transport and firmware sections through
NVM/antenna discovery, BT coexistence, exact PCI SoC latency, continuously
awake device power and scan configuration. Missing command versions/capabilities
fail before boot publication. It exposes identity only after all correlated
firmware receipts. Failed or dropped initialization cannot reset/retry that
owner; transport stop/fence/quarantine rules govern later destruction.
Configured boot is distinct from an authorized station or a usable netdev.

Kernel fixtures drive the actual owned RFH/TFH paths through ALIVE/NVM and
post-init command receipts, cancellation and duplicate-retry rejection.
Independent literal register/descriptor fixtures check context queue units,
PRPH apertures, TXv9/byte-count and RX48 geometry. These are software ownership
checks, with physical radio validation still pending.

### 3.5 Secure association and rekey entropy

Protected association obtains its SNonce from the fallible guarded hardware
entropy API before station firmware mutation; Open association needs no sample.
SAE uses the shared fallible Commit API and propagates unavailable entropy.
Pairwise rekey samples a fresh SNonce before replacing its pending candidate,
active PTK or replay state. Repeated M1 uses the retained response without
resampling. Partial failing samples remain private and are zeroized. Independent
key/replay fixtures cover failure, retry and cached retransmission; no timing
seed is admitted for production nonces.

## 4. References

- Linux `drivers/net/wireless/intel/iwlwifi/`
- Intel product briefs for AX200, AX210, etc.
- IEEE Std 802.11-2020.
