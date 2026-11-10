# USB-C port drivers — specification

## 1. Purpose & scope

Provide firmware-owned UCSI connectors and host-owned Type-C port controller
(TCPC) drivers. UCSI/firmware owns PD policy and the mux on ACPI laptops;
raw TCPC drivers supply the physical transport to `narf_usbpd::tcpc`.

## 2. Assumptions

UCSI requires an enabled ACPI `PNP0CA0`, a valid shared-memory `_CRS`, and
revision-1 `_DSM` read/write functions. PCI NHI enumeration alone does not
establish UCSI availability. Raw TCPC probing is suppressed when a PNP0CA0
exists to avoid competing with firmware for the same controller.

## 3. Public interface

- `dp_gpu_bridge::DpAltModeGpuBridge::exit_dp_mode(ConnectorId)` stops a
  retained GPU session on detach; the default is a no-op for bridges without
  a retained owner. `notify_dp_exited` snapshots the registry, invokes every
  bridge without the registry lock, and reports failure after delivering
  all exits. Each bridge releases only its own connector session. TCPM DP
  discovery retries a refused stop while detached and resets discovery and
  per-attach dispatch only after exit succeeds; reattach can then configure
  a fresh session. Contract renegotiation alone does not tear down DP.

- `ucsi::Transport` supplies bounded version, CCI, control and message accesses.
- `ucsi::Ppm<T>` owns and serializes async reset, initialization, polling and
  mode selection. Known UCSI versions 1.0/1.1/1.2/2.0/2.1/3.0 are accepted.
- `ucsi::connectors()` returns `Connector` snapshots keyed by `(ppm, number)`.
  `available` distinguishes a working PPM from transport failure. Snapshots
  expose connection/data/power state, firmware CAM/SVID/VDO, and orientation
  only when the UCSI version reports it. UCSI numbers are never GPU indices.
- `ucsi::register_observer(Arc<dyn ConnectorObserver>)` delivers the current
  snapshot and changes in task context, with no registry lock held.
- `Ppm::set_mode` requires firmware's alternate-mode override feature,
  validates PPM/connector identity and refreshes connection/mode support.
  Its mode-specific configuration is a Configure VDO, not a lane count.
- UCSI publishes `extcon::typec::FirmwareState` without programming a host mux.
- TCPC bindings publish one `TypecConnector` per binding through BOTH the
  extcon registry and `TYPEC_REGISTRY` at creation (`register_port`); the
  TCPM task mirrors attach, power/data roles, orientation, and DP Alt Mode
  entry/exit into it, and detach clears roles and entered modes. UCSI
  connectors take the same dual-registry creation path, so the Type-C class
  is the single publication path for both producers; a connector is owned
  by exactly one producer and is registered exactly once.
- Existing TCPC drivers register `Arc<dyn Tcpc>`; production I2C drivers retain
  their granted `Cap<I2cBus, Write>` and use capability-checked operations.
- EPR policy (`policy::SinkPolicy::evaluate_epr`,
  `policy::SourcePolicy::evaluate_epr_request`,
  `policy::SourceEprEntry` / `policy::SinkEprEntry`) is opt-in per port
  (`epr_capable`, default off). The source advertises the EPR Mode Capable
  bit on PDO #1 only, resolves EPR positions 8..=11 against `epr_pdos`,
  verifies the EPR_Request PDO copy byte-for-byte, and runs the §6.4.10.1
  entry sequence in `SourcePort` Ready (`EprEntryPending` state) with the
  cable-capability input fed via `SourcePort::set_cable_epr_capability`
  (fail-closed: unknown cable never yields Enter Succeeded). EPR_Request
  handling, EPR exit (re-advertise on SPR contract, Hard Reset on EPR
  contract), and `PortStepOutcome::EprModeEntered` are live on the source
  side; sink-side entry initiation awaits the policy-driven sink engine.
- `altmode_usb4::Usb4EntryPort` drives USB4 entry on a `TcpmPort`
  once its contract is live: source-attached (DFP) ports discover
  the partner and transmit the Enter_USB message on a USB4-capable
  Identity ACK; sink-attached (UFP) ports answer Discover Identity
  and record inbound Enter_USB parameters (`usb4_entered` /
  `entered_eudo`). Production task registration is a follow-up —
  real entry parameters must come from host capabilities and SOP'
  cable discovery, not fixture values.
- `TcpmPort` drives both power-role engines and routes role swaps:
  `initiate_{pr,dr,vconn}_swap` for the source engine,
  `initiate_sink_{pr,dr,vconn}_swap` for the sink engine. A completed
  PR_Swap flips the port-level state (`AttachedSrc` ↔ `AttachedSnk`)
  and the contract is renegotiated from scratch; data role and VConn
  supply carry across the swap. Sink swap answers are policy-gated by
  the `SinkPolicy` accept flags, wired into the sink engine at
  `TcpmPort` construction (default: reject all).
- `cable_discovery::CableDiscoveryPort` drives SOP' / SOP'' cable discovery
  from a live TCPM port: Discover Identity to SOP' post-contract, chaining to
  SOP'' for an active near plug reporting SOP'' support, with terminal states
  Done / NotPresent / Failed / Unsupported. Ports are registered in
  `CABLE_DISCOVERY_PORTS`; `cable_identity()` exposes the decoded
  `CableIdentity` (near plug plus far plug when obtained) and detach clears
  it. Terminal outcomes are also reported to the EPR entry hook
  (`SourcePort::set_cable_epr_capability`): Done reports the near plug's
  EPR capability, NotPresent / Failed / Unsupported report not-capable,
  and detach clears to unknown. DP Alt Mode discovery waits for `settled_for(connector)` so the two
  post-contract discovery tasks never race on the single TCPC RX FIFO.
  TCPCs with no SOP* transmit path (e.g. firmware-mediated TPS65987) settle
  as Unsupported.

## 4. Invariants

A single task owns each PPM. Command completion and acknowledgement complete
before another command starts; command errors still receive an ACK. Connector
changes are preserved independently. Transport/ACK failure or cancelled
commands poison the PPM until reset. Shared-memory accesses and all firmware
lengths/connector indices are checked. Failed workers publish unavailable
state, retry reset at bounded intervals, and stop after three failures.

PM gates prevent AML/shared-memory access during suspend; in-flight commands
return Busy to the system suspend caller. Resume requests a PPM reinitialization.
No hardware polling holds a spinlock or runs a custom busy-spin loop.

## 5. Architecture notes

The ACPI transport maps firmware RAM write-back, uses volatile little-endian
accesses and fences, and registers an ACPI Notify handler on each PNP0CA0
device (#1218): the handler only sets the owning task's kick flag (it never
issues commands or evaluates AML in Notify context), and the task's poll wait
re-checks the flag every 10 ms, so firmware-signaled events are observed
within ~10 ms. The Notify event value is ignored — Linux's `ucsi_acpi_notify`
likewise ignores it and just re-reads CCI — and polling every 100 ms
(1000 ms after failures) remains as the fallback for platforms whose firmware
never notifies and as the cadence for state drift without a Notify.
The protocol and fake-device tests run on x86_64 and aarch64.

## 6. Dependencies and references

`aml`, `memory`, `scheduler`, `time`, `power`, `drivers/extcon`, `drivers/i2c`,
`usbpd`, `capabilities`. UCSI register layouts/handshakes were checked against
`/usr/src/linux/drivers/usb/typec/ucsi/{ucsi.h,ucsi.c,ucsi_acpi.c,displayport.c}`.
The existing TPS65987 driver references TI SLVUBH2A/SLVSEX0F; FUSB302 references
ON Semiconductor FUSB302B/D and USB Type-C/PD specifications.

## 7. Stage assignment

Stage 5 laptop connector integration. Fake transports test status versions,
command/ACK sequencing, event preservation and failure poisoning. Physical
Lenovo firmware has not been exercised by this change.

## 8. Open work

Broader platform quirks.
GPU source modesetting and native USB4 tunneling are separate subsystems.
EPR follow-ups: EPR_Source_Capabilities / EPR_Sink_Capabilities extended-message
transport (§6.5.15) for EPR contract advertisement after entry; sink-side EPR
entry initiation once the sink engine is policy-driven; EPR keepalive timers
(tSinkEPRKeepAlive / tSourceEPRKeepAlive) and tEnterEPR; VCONN-Swap-during-entry
(the entry machine fails with NotVconnSource when the source is not already
the VCONN supplier).
