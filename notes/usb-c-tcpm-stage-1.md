# USB-C TCPM Stage 1 — source-side state machine + DP Alt Mode Stage 0

Builds on the existing TCPM sink engine in `narf_usbpd::tcpm::SinkPort`
and VDM/DP-Alt encoders in `narf_usbpd::vdm`.

- **Source PE** (`drivers/usbpd/src/tcpm.rs::SourcePort`) —
  `SRC_STARTUP → SRC_DISCOVERY → SRC_SEND_CAPABILITIES →
   SRC_NEGOTIATE_CAPABILITY → SRC_TRANSITION_SUPPLY → SRC_READY`,
  per USB-PD 3.1 §8.3.3.2. Fixed PDOs only; PPS/Variable/Battery
  Accept deferred to Stage 2.
- **Type-C dispatcher** (`TcpmPort`) — one chip + both engines.
  Classifies role from CC at attach (`Rd` → source; `Rp` → sink) and
  dispatches `step()`. Adds `Unattached / AttachedSnk / AttachedSrc /
  ErrorRecovery / Bist` states.
- **PD policy** (`drivers/usbpd/src/policy.rs`) — `SinkPolicy`
  (min voltage + op current, prefer-high-voltage knob, cap-mismatch
  fallback) and `SourcePolicy` (advertised PDOs + Accept/Wait/Reject
  decision on incoming Request RDOs).
- **DisplayPort Alt Mode** (`drivers/usbpd/src/altmode_dp.rs`) — wraps
  the existing `DpAltModeDriver` with a port-side driver that ships
  VDMs through `Tcpc::transmit` once the TCPM hits Ready. Logs
  `GPU-side display-pipe wiring deferred` on Enter Mode; scanout
  belongs to `drivers/gpu/` (separate agent).

## Wiring

`register_initcalls()` at `Stage::Late` walks every I²C bus, probes
FUSB302 (0x22) + TPS65987 (0x38). Per detected chip:

1. Register a `PortBinding` (debug snapshot).
2. Build a `TcpmPort` with `SinkPolicy::default()` (5 V / 3 A) and
   `SourcePolicy::default()` (5 V / 3 A Fixed PDO).
3. Register in `tcpm::TCPM_PORTS`.
4. Build a `DpAltModePort` against the same `TcpmPort`; register in
   `altmode_dp::DP_ALTMODE_PORTS`.
5. Spawn two async tasks: TCPM pump + DP Alt Mode discovery pump
   (idles until contract goes live).

On QEMU TCG with no I²C buses, the initcall logs
`tcpm: no PD chips detected (no I²C buses registered)` and exits
`NotPresent`.

## Smokes

- **policy**: 11 (sink picks 5V default; prefer-high-voltage opt-in;
  cap-mismatch fallback; current clamps to PDO max; empty caps None;
  Selection→RDO propagation; source default 5V/3A; source accepts
  in-budget, rejects over-budget, accepts cap_mismatch override,
  rejects unknown position).
- **tcpm**: 9 (source 5V/1.5A Accept → PS_RDY; rejects over-budget;
  role classification both ways; detach → Unattached; ERROR_RECOVERY;
  BIST idles; cap revocation; port registry).
- **altmode-dp**: 5 (NotReady pre-contract; full walk to Active over
  5 VDM exchanges; partner without DP SVID fails; registry; cap
  revocation).

## Out of scope (deferred)

- Power/data role swap (`PR_Swap` / `DR_Swap`) — Stage 2.
- PPS sink contracts — Stage 2.
- BIST emission (state stub only).
- Extended messages (battery status, country-info).
- Vconn-Powered / Audio Adapter Accessory.
- USB4 / Thunderbolt tunneling (separate agent).
- GPU display-pipe wiring once DP Alt Mode is up — `drivers/gpu/`.
